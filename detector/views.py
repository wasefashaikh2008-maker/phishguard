import os
import joblib
import pandas as pd
import requests
import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime
from django.utils import timezone
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import JsonResponse, HttpResponseForbidden
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth import get_user_model

from .forms import URLForm
from .models import URLCheck, CustomUser
from .validator import is_valid_url
from .report import generate_dynamic_report, risk_level, get_risk_description, get_risk_advice
from .features import extract_static_features

User = get_user_model()
BUNDLE_PATH = os.path.join(os.path.dirname(__file__), 'ml_model.joblib')


# =========================
# AUTH (unchanged)
# =========================

def register_user(request):
    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')

        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, "Username already taken")
        elif CustomUser.objects.filter(email=email).exists():
            messages.error(request, "Email already registered")
        else:
            user = CustomUser.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                user_type='2'
            )
            user.save()
            messages.success(request, "Registration successful.")
            return redirect('login')

    return render(request, 'detector/register.html')


def login_user(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect('index')
        else:
            messages.error(request, "Invalid credentials")
    return render(request, 'detector/login.html')


def logout_user(request):
    logout(request)
    return redirect('login')


# =========================
# LOAD MODEL
# =========================

def _load_model():
    if not os.path.exists(BUNDLE_PATH):
        return None
    return joblib.load(BUNDLE_PATH)


# =========================
# MAIN PAGE WITH DYNAMIC REPORT
# =========================

def index(request):
    form = URLForm()
    bundle = _load_model()

    if bundle is None:
        messages.error(request, "Model missing. Run train_model.py first.")
        return render(request, 'detector/index.html', {'form': form})

    model = bundle['model']
    cols = bundle['columns']
    threshold = bundle['threshold']
    info = bundle['model_info']

    if request.method == 'POST':
        form = URLForm(request.POST)

        if form.is_valid():
            url = form.cleaned_data['url']

            # Validate URL
            if not is_valid_url(url):
                messages.error(request, "Please enter a valid URL.")
                return render(request, 'detector/index.html', {'form': form})

            # Extract static features
            static_features = extract_static_features(url)

            # Create DataFrame for model
            x = pd.DataFrame([static_features])

            # Ensure all expected columns exist
            for col in cols:
                if col not in x.columns:
                    print(f"Warning: Missing feature {col}, setting to 0")
                    x[col] = 0

            x = x[cols]

            # Get Model Prediction
            proba = float(model.predict_proba(x)[0][1])
            final_risk = proba

            # Generate Dynamic Report
            report = generate_dynamic_report(url, final_risk, static_features)

            # Save History
            check = URLCheck.objects.create(
                user=request.user if request.user.is_authenticated else None,
                url=url,
                score=final_risk,
                result='phish' if final_risk >= threshold else 'legit'
            )

            # BLOCK UNSAFE SITES (optional - you can enable/disable this)
            BLOCK_UNSAFE_SITES = True  # Set to False to disable blocking

            if BLOCK_UNSAFE_SITES and report['should_block']:
                return render(request, 'detector/blocked.html', {
                    'report': report,
                    'url': url,
                    'check': check,
                    'model_info': info
                })

            # Render result page
            return render(request, 'detector/result.html', {
                'report': report,
                'url': url,
                'check': check,
                'model_info': info,
                'static_features': static_features
            })

    return render(request, 'detector/index.html', {'form': form})


# =========================
# HISTORY
# =========================

def history(request):
    if not request.user.is_authenticated:
        return redirect('login')

    rows = URLCheck.objects.filter(user=request.user).order_by('-created_at')
    return render(request, 'detector/history.html', {'rows': rows})


# =========================
# API
# =========================

def api_check(request):
    url = request.GET.get('url') or request.POST.get('url')

    if not url:
        return JsonResponse({'error': 'url required'}, status=400)

    if not is_valid_url(url):
        return JsonResponse({'error': 'Invalid URL'}, status=400)

    bundle = _load_model()

    if bundle is None:
        return JsonResponse({'error': 'model not loaded'}, status=500)

    model = bundle['model']
    cols = bundle['columns']
    threshold = bundle['threshold']

    # Extract features
    static_features = extract_static_features(url)
    x = pd.DataFrame([static_features])

    for col in cols:
        if col not in x.columns:
            x[col] = 0

    x = x[cols]

    # Prediction
    proba = float(model.predict_proba(x)[0][1])
    final_risk = proba

    # Generate report
    report = generate_dynamic_report(url, final_risk, static_features)

    return JsonResponse({
        'url': url,
        'risk_percent': round(final_risk * 100, 2),
        'risk_level': report['risk_level'],
        'label': 'phish' if final_risk >= threshold else 'legit',
        'critical_issues': report['critical_issues'],
        'warnings': report['warnings'],
        'safe_indicators': report['safe_indicators'],
        'technical': report['technical'],
        'should_block': report['should_block']
    })