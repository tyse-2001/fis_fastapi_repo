from django import forms

class DomainIpForm(forms.Form):
    domain_ip_name = forms.CharField(label='Domain/Ip name', max_length=100)