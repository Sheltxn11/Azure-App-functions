from flask import Flask, request, render_template_string
from azure.core.credentials import AzureKeyCredential
from azure.ai.formrecognizer import DocumentAnalysisClient
import os

app = Flask(__name__)

# Azure Form Recognizer credentials
endpoint = "https://trial3.cognitiveservices.azure.com/"
key = "df9c781b015546dcadbc3909de3aced2"
document_analysis_client = DocumentAnalysisClient(
    endpoint=endpoint, credential=AzureKeyCredential(key)
)

# HTML template
html_template = '''
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Invoice Processing</title>
  </head>
  <body>
    <h1>Upload Invoice</h1>
    <form action="/upload" method="post" enctype="multipart/form-data">
      <input type="file" name="file" accept="image/*" required>
      <button type="submit">Upload</button>
    </form>
    {% if results %}
    <h2>Invoice Details:</h2>
    <ul>
      {% for result in results %}
      <li>{{ result }}</li>
      {% endfor %}
    </ul>
    {% endif %}
  </body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(html_template, results=None)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return render_template_string(html_template, results=["No file part"])

    file = request.files['file']
    if file.filename == '':
        return render_template_string(html_template, results=["No selected file"])

    if file:
        poller = document_analysis_client.begin_analyze_document("prebuilt-invoice", file)
        invoices = poller.result()

        results = []
        for idx, invoice in enumerate(invoices.documents):
            results.append(f"--------Recognizing invoice #{idx + 1}--------")
            company_name = invoice.fields.get("VendorName")
            if company_name:
                results.append(f"Company Name: {company_name.value} has confidence: {company_name.confidence}")

            invoice_number = invoice.fields.get("InvoiceId")
            if invoice_number:
                results.append(f"Invoice Number: {invoice_number.value} has confidence: {invoice_number.confidence}")

            invoice_date = invoice.fields.get("InvoiceDate")
            if invoice_date:
                results.append(f"Invoice Date: {invoice_date.value} has confidence: {invoice_date.confidence}")

            due_date = invoice.fields.get("DueDate")
            if due_date:
                results.append(f"Due Date: {due_date.value} has confidence: {due_date.confidence}")

            subtotal = invoice.fields.get("SubTotal")
            if subtotal:
                results.append(f"Subtotal: {subtotal.value} has confidence: {subtotal.confidence}")

            total_tax = invoice.fields.get("TotalTax")
            if total_tax:
                results.append(f"Tax: {total_tax.value} has confidence: {total_tax.confidence}")

            amount_due = invoice.fields.get("AmountDue")
            if amount_due:
                results.append(f"Total Amount: {amount_due.value} has confidence: {amount_due.confidence}")

            results.append("----------------------------------------")

        return render_template_string(html_template, results=results)

if __name__ == '__main__':
    app.run(debug=True)

