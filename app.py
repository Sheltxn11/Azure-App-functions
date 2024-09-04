from flask import Flask, request, jsonify, render_template
from azure.core.credentials import AzureKeyCredential
from azure.ai.formrecognizer import DocumentAnalysisClient

app = Flask(__name__)

# Azure Form Recognizer credentials
azure_endpoint = "https://trial3.cognitiveservices.azure.com/"
azure_key = "df9c781b015546dcadbc3909de3aced2"

# Initialize DocumentAnalysisClient
document_analysis_client = DocumentAnalysisClient(
    endpoint=azure_endpoint, credential=AzureKeyCredential(azure_key)
)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload-invoice', methods=['POST'])
def upload_invoice():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    with file.stream as doc_file:
        poller = document_analysis_client.begin_analyze_document("prebuilt-invoice", doc_file)
        result = poller.result()

    invoice = result.documents[0] if result.documents else None

    if not invoice:
        return jsonify({"error": "No invoice found in the document"}), 400

    company_name = invoice.fields.get("VendorName").value if invoice.fields.get("VendorName") else 'N/A'
    invoice_number = invoice.fields.get("InvoiceId").value if invoice.fields.get("InvoiceId") else 'N/A'
    invoice_date = invoice.fields.get("InvoiceDate").value if invoice.fields.get("InvoiceDate") else 'N/A'
    due_date = invoice.fields.get("DueDate").value if invoice.fields.get("DueDate") else 'N/A'
    subtotal = invoice.fields.get("SubTotal").value if invoice.fields.get("SubTotal") else 'N/A'
    advance = invoice.fields.get("AdvancePayment").value if invoice.fields.get("AdvancePayment") else 'N/A'
    discount = invoice.fields.get("Discount").value if invoice.fields.get("Discount") else 'N/A'
    total_tax = invoice.fields.get("TotalTax").value if invoice.fields.get("TotalTax") else 'N/A'
    total = invoice.fields.get("InvoiceTotal").value if invoice.fields.get("InvoiceTotal") else 'N/A'

    REQUIRED_FIELDS = {
        "Company_Name": company_name,
        "invoice_number": invoice_number,
        "invoice_date": invoice_date,
        "due_date": due_date,
        "advance": advance,
        "discount": discount,
        "subtotal": subtotal,
        "tax": total_tax,
        "total": total
    }

    print("Extracted Fields:", REQUIRED_FIELDS)  # Debug print

    items = invoice.fields.get("Items")
    ITEMS = []
    if items and items.value:
        for item in items.value:
            item_description = item.value.get("Description").value if item.value.get("Description") else 'N/A'
            item_quantity = item.value.get("Quantity").value if item.value.get("Quantity") else 'N/A'
            
            unit_price_obj = item.value.get("UnitPrice")
            unit_price = f"{unit_price_obj.value}" if unit_price_obj else 'N/A'
            
            discount_obj = item.value.get("Discount")
            discount = f"{discount_obj.value}" if discount_obj else 'N/A'
            
            tax_obj = item.value.get("Tax")
            tax = f"{tax_obj.value}" if tax_obj else 'N/A'
            
            amount_obj = item.value.get("Amount")
            total = f"{amount_obj.value}" if amount_obj else 'N/A'

            ITEMS.append({
                "description": item_description,
                "quantity": item_quantity,
                "unit_price": unit_price,
                "discount": discount,
                "tax": tax,
                "total": total
            })

    print("Extracted Items:", ITEMS)  # Debug print

    return render_template('result.html', fields=REQUIRED_FIELDS, items=ITEMS)


# HTML Page
@app.route('/')
def upload_form():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
