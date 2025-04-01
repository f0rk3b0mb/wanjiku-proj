from io import BytesIO
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
import datetime

def generate_users_report(users):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter))
    elements = []
    styles = getSampleStyleSheet()
    custom_style = ParagraphStyle('CustomStyle', parent=styles['Normal'])
    custom_style.alignment = 1
    title = Paragraph("<h6>User Report</h6>", custom_style)
    elements.append(title)
    elements.append(Spacer(1, 12))

    users_table_data = [['User ID', 'Username', 'Email', 'Role', 'Is Approved', 'Date Registered']]
    for user in users:
        users_table_data.append([str(user.id), user.username, user.email, user.role, user.is_approved, str(user.date_registered)])

    users_table = Table(users_table_data)
    users_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),  
        ('WORDWRAP', (0, 1), (-1, -1)),  
    ]))

    elements.append(users_table)

    elements.append(Spacer(1, 12))

    footer = Paragraph(f"Generated on {datetime.date.today()}", custom_style)
    elements.append(footer)

    # Build the combined PDF report
    doc.build(elements)
    buffer.seek(0)
    return buffer.read()


def generate_files_report(files):

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter))
    elements = []
    styles = getSampleStyleSheet()
    custom_style = ParagraphStyle('CustomStyle', parent=styles['Normal'])
    custom_style.alignment = 1
    title = Paragraph("<h6>files Report</h6>", custom_style)
    elements.append(title)

    # Add a spacer for separation
    elements.append(Spacer(1, 12))


    # Create a table to display the Files Report
    files_table_data = [['File ID', 'File Name', 'SHA256 Sum', 'Owner ID', 'Upload Date']]
    for file in files:
        files_table_data.append([str(file.id), file.file_name, file.sha256sum, str(file.owner_id), str(file.upload_date)])

    files_table = Table(files_table_data)
    files_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'), 
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),  
        ('WORDWRAP', (0, 1), (-1, -1)),  
    ]))

    elements.append(files_table)

    elements.append(Spacer(1, 12))

    footer = Paragraph(f"Generated on {datetime.date.today()}", custom_style)
    elements.append(footer)

    # Build the combined PDF report
    doc.build(elements)
    buffer.seek(0)
    return buffer.read()


def generate_backups_report(backups):

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter))
    elements = []
    styles = getSampleStyleSheet()
    custom_style = ParagraphStyle('CustomStyle', parent=styles['Normal'])
    custom_style.alignment = 1
    title = Paragraph("<h6>Backups Report</h6>", custom_style)
    elements.append(title)

    # Add a spacer for separation
    elements.append(Spacer(1, 12))


    # Create a table to display the Files Report
    files_table_data = [['File ID', 'File Name', "Path", "Date created"]]
    for file in backups:
        files_table_data.append([str(file.id), file.file_name, file.file_path,str(file.date_created)])

    files_table = Table(files_table_data)
    files_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'), 
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),  
        ('WORDWRAP', (0, 1), (-1, -1)),  
    ]))

    elements.append(files_table)

    elements.append(Spacer(1, 12))

    footer = Paragraph(f"Generated on {datetime.date.today()}", custom_style)
    elements.append(footer)

    # Build the combined PDF report
    doc.build(elements)
    buffer.seek(0)
    return buffer.read()