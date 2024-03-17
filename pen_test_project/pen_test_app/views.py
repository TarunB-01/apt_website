import os
import subprocess
import time
from django.conf import settings
from django.shortcuts import get_object_or_404, render,redirect
import requests
from .models import Users
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
import os
import subprocess
import time
import requests
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.files.base import ContentFile

def home(request):
    return render(request,'home.html')

def registerView(request):
    if request.method == 'POST':
        name = request.POST['username']
        password = request.POST['password']

        check_user = Users.objects.filter(username=name).count()

        if(check_user > 0):
            messages.error(request, 'Username is already taken')
            return redirect('reg-form')
        else:
            Users.objects.create(username=name, password=password)
            messages.success(request, 'Account created successfully, Please Sign In')
            return redirect('reg-form')
    else:
        return render(request, 'signup.html')
    
def loginView(request):
    if request.method == 'POST':
        name = request.POST.get('username')
        password = request.POST.get('password')
        
        # Query the database to check if the email and password match
        user = Users.objects.filter(username=name, password=password).first()
        
        if user is not None:
            # If user exists, set session variable or perform any other desired actions
            request.session['user_id'] = user.id  # Example: Setting user_id in session
            return render(request,'dashboard.html')  # Redirect to the dashboard page after successful login
        else:
            messages.error(request, 'Invalid email or password')  # Display error message if authentication fails
            return redirect('login')  # Redirect back to the login page
    else:
        return render(request, 'login.html')
@login_required
def dashboard(request):
        return render(request, 'dashboard.html')

# views.py

import logging
import os
import subprocess
import requests
import time
from django.http import HttpResponse
from django.shortcuts import render

logger = logging.getLogger(__name__)

import os
import subprocess
import requests
import json
import time
from django.http import JsonResponse
from .models import ScanStatus,Report

def fetch_scan_status(request):
    # Retrieve the status of all URLs from the ScanStatus model
    statuses = ScanStatus.objects.all().values('url', 'status')

    # Convert QuerySet to dictionary
    status_dict = {status['url']: status['status'] for status in statuses}

    return JsonResponse(status_dict)

@csrf_exempt  # Temporary measure to handle POST request without CSRF token
def submit_url_view(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        # Process the submitted URL and perform necessary actions (e.g., scanning)
        # For demonstration purposes, let's assume we create a ScanStatus object
        # with the initial status set to 'scheduled'
        ScanStatus.objects.create(url=url, status='scheduled')
        return render(request, 'status.html', {'url': url})
    return render(request, 'scan_form.html')

def scan_with_nmap_and_zap_view(request):
    # Get URL from request
    url = request.GET.get('url')

    # Create a ScanStatus object with status 'scheduled'
    # Nmap scanning (asynchronous)
    nmap_url = url.strip().replace("http://", "").replace("https://", "")
    nmap_output_file = os.path.join(os.getcwd(), 'nmap_output.txt')
    nmap_command = ['nmap', '-oN', nmap_output_file, nmap_url]
    subprocess.Popen(nmap_command)  # Start scanning asynchronously

    # Set up the ZAP API URL and API key
    zap_api_url = "http://localhost:8080"
    api_key = "u14biiejgnnmbigmkib12t10gg"  # Replace "your_api_key" with your actual API key

    # Start ZAP in daemon mode (optional if ZAP is already running)
    requests.get(f"{zap_api_url}/JSON/core/action/newSession/?apikey={api_key}")

    # Initiating the spider scan (asynchronous)
    resp = requests.get(f"{zap_api_url}/JSON/spider/action/scan/?zapapiformat=JSON&url={url}&apikey={api_key}")
    spider_scan_status = resp.status_code  # Get the status code of the response

    # Initiating the active scan (asynchronous)
    resp = requests.get(f"{zap_api_url}/JSON/ascan/action/scan/?zapapiformat=JSON&url={url}&apikey={api_key}")
    active_scan_status = resp.status_code  # Get the status code of the response

    # Update the status based on the completion of ZAP scans (since Nmap completion status is not available)
    if spider_scan_status == 100 and active_scan_status == 100:
        # Both scans completed successfully
        status = 'completed'
    else:
        # Scans still in progress
        status = 'in progress'

    # Update the status in the database
    ScanStatus.objects.filter(url=url).update(status=status)

    # Return the status response
    data = {
        'url': url,
        'status': status
    }
    return JsonResponse(data)

def scan_form(request):
    return render(request, 'scan_form.html')


def scan_with_nmap_and_zap_view(request):
    # Get URL from request
    url = request.GET.get('url')

    # Create a ScanStatus object with status 'scheduled'
    scan_status = ScanStatus.objects.create(url=url, status='scheduled')

    # Nmap scanning
    nmap_url = url.strip().replace("http://", "").replace("https://", "")
    nmap_output_file = os.path.join(os.getcwd(), 'nmap_output.txt')
    nmap_command = ['nmap', '-oN', nmap_output_file, nmap_url]
    subprocess.Popen(nmap_command)  # Start scanning asynchronously

    # Set up the ZAP API URL and API key
    zap_api_url = "http://localhost:8080"
    api_key = "u14biiejgnnmbigmkib12t10gg"  # Replace "your_api_key" with your actual API key

    # Start ZAP in daemon mode (optional if ZAP is already running)
    requests.get(f"{zap_api_url}/JSON/core/action/newSession/?apikey={api_key}")

    # Initiating the spider scan (asynchronous)
    resp = requests.get(f"{zap_api_url}/JSON/spider/action/scan/?zapapiformat=JSON&url={url}&apikey={api_key}")
    spider_scan_status = resp.status_code  # Get the status code of the response

    # Initiating the active scan (asynchronous)
    resp = requests.get(f"{zap_api_url}/JSON/ascan/action/scan/?zapapiformat=JSON&url={url}&apikey={api_key}")
    active_scan_status = resp.status_code  # Get the status code of the response

    # Update the status based on the completion of ZAP scans
    if spider_scan_status == 100 and active_scan_status == 100:
        # Both scans completed successfully
        status = 'completed'
    else:
        # Scans still in progress
        status = 'in progress'

    # Check if both Nmap and ZAP scans are completed
    if status == 'completed':
        # Retrieve the ZAP scan results
        zap_report_url = f"{zap_api_url}/OTHER/core/other/htmlreport/"
        zap_report_response = requests.get(zap_report_url)
        zap_report_content = zap_report_response.content

        # Generate the combined report
        combined_report_path = generate_combined_report(nmap_output_file, zap_report_content)

        # Save the combined report to the database
        report = Report.objects.create(url=url)
        report.report.save(os.path.basename(combined_report_path), ContentFile(open(combined_report_path, 'rb').read()))

    # Update the status in the database
    scan_status.status = status
    scan_status.save()

    # Return the status response
    data = {
        'url': url,
        'status': status
    }
    return JsonResponse(data)
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def generate_combined_report(nmap_output_file, zap_report_content):
    # Retrieve the Nmap scan results
    try:
        with open(nmap_output_file, "rb") as f:
            nmap_report_content = f.read()
    except Exception as e:
        print("Error generating Nmap report:", str(e))
        return None

    # Create a PDF report combining both reports
    combined_report_path = os.path.join(os.getcwd(), 'combined_report.pdf')
    c = canvas.Canvas(combined_report_path, pagesize=letter)
    c.drawString(100, 800, "Nmap Report:")
    c.drawString(100, 780, nmap_report_content.decode())
    c.drawString(100, 750, "ZAP Report:")
    c.drawString(100, 730, zap_report_content)  # Use the actual ZAP report content
    c.save()

    return combined_report_path

def download_report(request, report_id):
    report = get_object_or_404(Report, pk=report_id)
    report_file_path = os.path.join(settings.MEDIA_ROOT, report.report_file.name)

    if os.path.exists(report_file_path):
        with open(report_file_path, 'rb') as f:
            response = HttpResponse(f.read(), content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="{os.path.basename(report_file_path)}"'
            return response
    else:
        return HttpResponse("File not found", status=404)