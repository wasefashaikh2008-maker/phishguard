from django.contrib.auth import authenticate, login,logout
from django.shortcuts import render, redirect
from django.contrib import messages
from django.conf import settings
from datetime import timedelta
from django.contrib.auth.decorators import login_required
from detector.models import URLCheck, CustomUser
from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
import random
from django.utils import timezone
from datetime import datetime
from django.db.models import Q
from django.shortcuts import render, get_object_or_404
from django.db.models import Count
from django.contrib.auth.hashers import make_password
from datetime import datetime, timedelta
from django.utils.timezone import now
from django.db.models import Count
User = get_user_model()

def BASE(request):
       return render(request,'base.html')


@login_required(login_url = '/')
def Dashboard(request):
    today = now().date()
    yesterday = today - timedelta(days=1)
    seven_days_ago = today - timedelta(days=7)
    month_start = today.replace(day=1)

    today_count = URLCheck.objects.filter(created_at__date=today).count()
    yesterday_count = URLCheck.objects.filter(created_at__date=yesterday).count()
    seven_days_count = URLCheck.objects.filter(created_at__date__gte=seven_days_ago).count()
    month_count = URLCheck.objects.filter(created_at__date__gte=month_start).count()
    reguser_count = CustomUser.objects.filter(user_type='2').count()
    context = {'reguser_count':reguser_count,
        "today_count": today_count,
        "yesterday_count": yesterday_count,
        "seven_days_count": seven_days_count,
        "month_count": month_count,}

    return render(request,'dashboard.html',context)

def today_checks(request):
    today = now().date()
    checks = URLCheck.objects.filter(created_at__date=today)
    return render(request, "today_checks.html", {"checks": checks})

def yesterday_checks(request):
    yesterday = now().date() - timedelta(days=1)
    checks = URLCheck.objects.filter(created_at__date=yesterday)
    return render(request, "yesterday_checks.html", {"checks": checks})

def seven_days_checks(request):
    seven_days_ago = now().date() - timedelta(days=7)
    checks = URLCheck.objects.filter(created_at__date__gte=seven_days_ago)
    return render(request, "seven_days_checks.html", {"checks": checks})

def month_checks(request):
    today = now().date()
    checks = URLCheck.objects.filter(created_at__month=today.month)
    return render(request, "month_checks.html", {"checks": checks})

def AdDMIN_LOGIN(request):
    return render(request,'login.html')


def doLogin(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            if user.is_active:
                login(request, user)
                if user.user_type == '1':
                    return redirect('dashboard')
                elif user.user_type == '2':
                    return redirect('index')
                else:
                    messages.error(request, 'Invalid user type.')
            else:
                messages.error(request, 'Account is inactive.')
        else:
            messages.error(request, 'Invalid username or password.')

        return redirect('admin_login')

    messages.error(request, 'Invalid request method.')
    return redirect('admin_login')

def doLogout(request):
    logout(request)
    return redirect('admin_login')

def reset_password(request):
    if request.method == "POST":
        email = request.POST.get('email')
        new_password = request.POST.get('newpassword')

        try:
            user = CustomUser.objects.get(email=email)
            user.password = make_password(new_password)  # Hash the new password
            user.save()
            messages.success(request, "Your password has been successfully changed.")
            return redirect('reset_password')  # Redirect to login page
        except CustomUser.DoesNotExist:
            messages.error(request, "Invalid email or mobile number.")

    return render(request, 'reset_password.html')


@login_required(login_url='/')
def AdDMIN_PROFILE(request):
    user = CustomUser.objects.get(id=request.user.id)
    if user.user_type == '1':
        return render(request, 'admin_profile.html', {'user': user})

   ## if user.user_type == '2':
     ##   return render(request, 'students/student-profile.html', {'user': user})


@login_required(login_url = '/')
def ADMIN_PROFILE_UPDATE(request):
    if request.method == "POST":
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        try:
            customuser = CustomUser.objects.get(id = request.user.id)
            customuser.first_name = first_name
            customuser.last_name = last_name
            customuser.save()
            messages.success(request,"Your profile has been updated successfully")
            return redirect('admin_profile')

        except:
            messages.error(request,"Your profile updation has been failed")
    return render(request, 'admin_profile.html')


@login_required(login_url='/')
def CHANGE_PASSWORD(request):
    user = CustomUser.objects.get(id=request.user.id)

    if request.method == "POST":
        current = request.POST["cpwd"]
        new_pas = request.POST["npwd"]

        if user.check_password(current):
            user.set_password(new_pas)
            user.save()
            messages.success(request, 'Password changed successfully!')

            # Re-login user
            login(request, user)
            return redirect("change_password")
        else:
            messages.error(request, 'Current password is incorrect.')
            return redirect("change_password")

    # Choose template based on user_type
    if user.user_type == '1':
        return render(request, 'change-password.html', {"data": user})


@login_required(login_url='/')
def registeres_users(request):
    user_list = CustomUser.objects.filter(user_type='2').order_by('-id')  # works fine now
    paginator = Paginator(user_list, 10)
    page_number = request.GET.get('page')
    regusers = paginator.get_page(page_number)
    return render(request, 'reg_users.html', {'regusers': regusers})


@login_required(login_url='/')
def DELETE_REGUSERS(request,id):
    regusers = CustomUser.objects.get(id=id)
    regusers.delete()
    messages.success(request,'Record Delete Succeesfully!!!')
    return redirect('registeres_users')


@login_required(login_url='/')
def user_urlcheck_history(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    urlcheck = URLCheck.objects.filter(user=user).order_by('-created_at')
    return render(request, 'user_check_url.html', {
        'urlcheck': urlcheck,
        'target_user': user,  # Renamed to avoid confusion with request.user
        'is_admin_view': True  # Add this flag for template
    })


@login_required(login_url='/Login')  # or use name='login' and reverse URL if preferred
def Between_Date_Report(request):
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    app = []
    error_message = None
    paginated_app = []

    if start_date and end_date:
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()

            if start_date_obj > end_date_obj:
                error_message = "Start date cannot be after end date."
            else:
                app = URLCheck.objects.filter(
                    created_at__range=(start_date_obj, end_date_obj)
                ).order_by('-created_at')

                # Add pagination
                paginator = Paginator(app, 10)
                page_number = request.GET.get('page')
                paginated_app = paginator.get_page(page_number)

        except ValueError:
            error_message = "Invalid date format. Please use YYYY-MM-DD."

    context = {
        'paginated_app': paginated_app,
        'start_date': start_date,
        'end_date': end_date,
        'error_message': error_message
    }

    return render(request, 'betdates-report.html', context)



@login_required(login_url='/')
def Search_URLCHECK(request):
    if request.method == "GET":
        query = request.GET.get('query', '')
        if query:
            app = URLCheck.objects.filter(
                Q(user__email__icontains=query) |
                Q(user__first_name__icontains=query) |
                Q(user__last_name__icontains=query)
            ).distinct()

            if app.exists():
                messages.success(request, f"Results for: '{query}'")
            else:
                messages.warning(request, f"No results found for: '{query}'")

            return render(request, 'search.html', {'app': app, 'query': query})
        else:

            return render(request, 'search.html')