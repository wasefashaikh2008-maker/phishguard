from django import forms

class URLForm(forms.Form):
    url = forms.CharField(label='Website URL', widget=forms.TextInput(attrs={
        'placeholder': 'e.g., https://example.com/login?ref=...',
        'class': 'form-control'
    }))
