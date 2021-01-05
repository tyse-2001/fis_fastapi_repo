from django import forms

class DomainIpForm(forms.Form):
    domain_ip_name = forms.CharField(
        label='Domain/Ip name',
        max_length=255,
        widget=forms.TextInput(
            attrs={
                'placeholder': 'e.g. google.com'
            }
        )
    )

class FilesForm(forms.Form):
    file_name = forms.CharField(
        label='File hash',
        max_length=64,
        widget=forms.TextInput(
            attrs={
                'placeholder': 'SHA256 hash'
            }
        )
    )
