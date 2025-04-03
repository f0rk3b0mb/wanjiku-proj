from io import BytesIO
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.units import inch
import datetime
from database import File, User, Backups, Role
from utils import calculate_sha256
import os

def generate_certificate_verification_report(start_date=None, end_date=None):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter))
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'])
    title_style.alignment = 1
    title = Paragraph("Certificate Verification Report", title_style)
    elements.append(title)
    elements.append(Spacer(1, 20))
    
    # Date Range
    date_style = ParagraphStyle('DateStyle', parent=styles['Normal'])
    date_style.alignment = 1
    date_range = f"Period: {start_date.strftime('%Y-%m-%d') if start_date else 'All time'} to {end_date.strftime('%Y-%m-%d') if end_date else 'Present'}"
    elements.append(Paragraph(date_range, date_style))
    elements.append(Spacer(1, 20))
    
    # Certificate Data
    query = File.query.filter(File.certificate_id.isnot(None))
    if start_date:
        query = query.filter(File.upload_date >= start_date)
    if end_date:
        query = query.filter(File.upload_date <= end_date)
    certificates = query.all()
    
    # Summary Statistics
    total_certificates = len(certificates)
    verified_certificates = sum(1 for cert in certificates if cert.blockchain_tx)
    
    summary_data = [
        ['Total Certificates', str(total_certificates)],
        ['Verified Certificates', str(verified_certificates)],
        ['Verification Rate', f"{(verified_certificates/total_certificates*100):.2f}%" if total_certificates > 0 else "0%"]
    ]
    
    summary_table = Table(summary_data)
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 20))
    
    # Detailed Certificate Table
    table_data = [['Certificate ID', 'Student Name', 'Degree', 'Issue Date', 'Verification Status', 'Blockchain TX']]
    for cert in certificates:
        student_name = cert.file_name.split('_')[0] if '_' in cert.file_name else 'Unknown'
        verification_status = 'Verified' if cert.blockchain_tx else 'Pending'
        table_data.append([
            cert.certificate_id,
            student_name,
            'N/A',  # Would need to extract from certificate content
            cert.upload_date.strftime('%Y-%m-%d'),
            verification_status,
            cert.blockchain_tx[:10] + '...' if cert.blockchain_tx else 'N/A'
        ])
    
    cert_table = Table(table_data)
    cert_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('WORDWRAP', (0, 1), (-1, -1))
    ]))
    elements.append(cert_table)
    
    # Footer
    footer = Paragraph(f"Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal'])
    elements.append(Spacer(1, 20))
    elements.append(footer)
    
    doc.build(elements)
    buffer.seek(0)
    return buffer.read()

def generate_file_integrity_report(start_date=None, end_date=None):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter))
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'])
    title_style.alignment = 1
    title = Paragraph("File Integrity Report", title_style)
    elements.append(title)
    elements.append(Spacer(1, 20))
    
    # Date Range
    date_style = ParagraphStyle('DateStyle', parent=styles['Normal'])
    date_style.alignment = 1
    date_range = f"Period: {start_date.strftime('%Y-%m-%d') if start_date else 'All time'} to {end_date.strftime('%Y-%m-%d') if end_date else 'Present'}"
    elements.append(Paragraph(date_range, date_style))
    elements.append(Spacer(1, 20))
    
    # Query files
    query = File.query
    if start_date:
        query = query.filter(File.upload_date >= start_date)
    if end_date:
        query = query.filter(File.upload_date <= end_date)
    files = query.all()
    
    # Summary Statistics
    total_files = len(files)
    total_size = sum(file.file_size for file in files)
    verified_files = sum(1 for file in files if file.blockchain_tx)
    
    summary_data = [
        ['Total Files', str(total_files)],
        ['Total Storage Used', f"{total_size / (1024*1024):.2f} MB"],
        ['Verified Files', str(verified_files)],
        ['Verification Rate', f"{(verified_files/total_files*100):.2f}%" if total_files > 0 else "0%"]
    ]
    
    summary_table = Table(summary_data)
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 20))
    
    # Detailed File Table
    table_data = [['File Name', 'Size (MB)', 'Upload Date', 'Encryption Status', 'Verification Status', 'Blockchain TX']]
    for file in files:
        encryption_status = 'Encrypted' if os.path.exists(file.file_path) else 'Not Found'
        verification_status = 'Verified' if file.blockchain_tx else 'Pending'
        table_data.append([
            file.file_name,
            f"{file.file_size / (1024*1024):.2f}",
            file.upload_date.strftime('%Y-%m-%d'),
            encryption_status,
            verification_status,
            file.blockchain_tx[:10] + '...' if file.blockchain_tx else 'N/A'
        ])
    
    file_table = Table(table_data)
    file_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('WORDWRAP', (0, 1), (-1, -1))
    ]))
    elements.append(file_table)
    
    # Footer
    footer = Paragraph(f"Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal'])
    elements.append(Spacer(1, 20))
    elements.append(footer)
    
    doc.build(elements)
    buffer.seek(0)
    return buffer.read()

def generate_backup_health_report(start_date=None, end_date=None):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter))
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'])
    title_style.alignment = 1
    title = Paragraph("Backup Health Report", title_style)
    elements.append(title)
    elements.append(Spacer(1, 20))
    
    # Date Range
    date_style = ParagraphStyle('DateStyle', parent=styles['Normal'])
    date_style.alignment = 1
    date_range = f"Period: {start_date.strftime('%Y-%m-%d') if start_date else 'All time'} to {end_date.strftime('%Y-%m-%d') if end_date else 'Present'}"
    elements.append(Paragraph(date_range, date_style))
    elements.append(Spacer(1, 20))
    
    # Query backups
    query = Backups.query
    if start_date:
        query = query.filter(Backups.date_created >= start_date)
    if end_date:
        query = query.filter(Backups.date_created <= end_date)
    backups = query.all()
    
    # Summary Statistics
    total_backups = len(backups)
    total_size = sum(float(backup.file_size) for backup in backups if backup.file_size)
    verified_backups = sum(1 for backup in backups if backup.sha256sum)
    
    summary_data = [
        ['Total Backups', str(total_backups)],
        ['Total Backup Size', f"{total_size / (1024*1024):.2f} MB"],
        ['Verified Backups', str(verified_backups)],
        ['Verification Rate', f"{(verified_backups/total_backups*100):.2f}%" if total_backups > 0 else "0%"]
    ]
    
    summary_table = Table(summary_data)
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 20))
    
    # Detailed Backup Table
    table_data = [['Backup Name', 'Size (MB)', 'Creation Date', 'Verification Status', 'Path']]
    for backup in backups:
        verification_status = 'Verified' if backup.sha256sum else 'Pending'
        table_data.append([
            backup.file_name,
            f"{float(backup.file_size) / (1024*1024):.2f}" if backup.file_size else 'N/A',
            backup.date_created,
            verification_status,
            backup.file_path
        ])
    
    backup_table = Table(table_data)
    backup_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('WORDWRAP', (0, 1), (-1, -1))
    ]))
    elements.append(backup_table)
    
    # Footer
    footer = Paragraph(f"Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal'])
    elements.append(Spacer(1, 20))
    elements.append(footer)
    
    doc.build(elements)
    buffer.seek(0)
    return buffer.read()

def generate_verification_report(verification_result):
    # Create reports directory if it doesn't exist
    reports_dir = 'reports'
    os.makedirs(reports_dir, exist_ok=True)
    
    # Generate unique filename with timestamp
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"verification_report_{timestamp}.pdf"
    filepath = os.path.join(reports_dir, filename)
    
    # Generate PDF
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'])
    title_style.alignment = 1
    title = Paragraph("File Verification Report", title_style)
    elements.append(title)
    elements.append(Spacer(1, 20))
    
    # Timestamp
    timestamp = Paragraph(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal'])
    elements.append(timestamp)
    elements.append(Spacer(1, 20))
    
    # Verification Status
    status_style = ParagraphStyle('StatusStyle', parent=styles['Heading2'])
    status_style.alignment = 1
    status_color = colors.green if verification_result['verified'] else colors.red
    status_text = "VERIFICATION SUCCESSFUL" if verification_result['verified'] else "VERIFICATION FAILED"
    status = Paragraph(f"<font color='{status_color}'>{status_text}</font>", status_style)
    elements.append(status)
    elements.append(Spacer(1, 20))
    
    # File Details
    details_data = [
        ['File Name', verification_result['details']['file_name']],
        ['Certificate ID', verification_result['details']['certificate_id']],
        ['Verification Status', 'Verified' if verification_result['verified'] else 'Failed'],
        ['Message', verification_result['message']]
    ]
    
    details_table = Table(details_data)
    details_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(details_table)
    elements.append(Spacer(1, 20))
    
    # Hash Comparison
    hash_data = [
        ['Hash Type', 'Value'],
        ['Calculated Hash', verification_result['details']['calculated_hash']],
        ['Stored Hash', verification_result['details']['stored_hash']]
    ]
    
    hash_table = Table(hash_data)
    hash_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('WORDWRAP', (0, 1), (-1, -1))
    ]))
    elements.append(hash_table)
    
    # Footer
    footer = Paragraph("This report was automatically generated by the Secure File Storage System", styles['Normal'])
    elements.append(Spacer(1, 20))
    elements.append(footer)
    
    doc.build(elements)
    
    # Save the PDF to file
    with open(filepath, 'wb') as f:
        f.write(buffer.getvalue())
    
    # Return both the file path and the PDF data
    return {
        'filepath': filepath,
        'filename': filename,
        'pdf_data': buffer.getvalue()
    }