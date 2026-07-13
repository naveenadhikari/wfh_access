import os
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

def get_saml_config(request):
    """
    Builds the python3-saml config dynamically based on the current request.
    This ensures the SP Entity ID and ACS URLs match the host we are serving from.
    """
    
    # In production with a reverse proxy, you might need to handle X-Forwarded-* headers,
    
    url_data = urlparse(request.url)
    
    scheme = request.scheme
    host = request.host
    base_url = f"{scheme}://{host}"
    
    idp_cert = ""
    idp_entity_id = ""
    idp_sso_url = ""
    
    # We will read the certificate and IdP settings from the saved idp_metadata.xml
    metadata_path = os.path.join(os.path.dirname(__file__), "saml", "idp_metadata.xml")
    if os.path.exists(metadata_path):
        try:
            tree = ET.parse(metadata_path)
            root = tree.getroot()
            namespaces = {'md': 'urn:oasis:names:tc:SAML:2.0:metadata', 'ds': 'http://www.w3.org/2000/09/xmldsig#'}
            
            # Extract Entity ID
            idp_entity_id = root.attrib.get('entityID', '')
            
            # Extract SingleSignOnService URL (HTTP-Redirect)
            sso_node = root.find('.//md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]', namespaces)
            if sso_node is not None:
                idp_sso_url = sso_node.attrib.get('Location', '')
            
            # Find the first signing certificate
            cert_node = root.find('.//md:KeyDescriptor[@use="signing"]//ds:X509Certificate', namespaces)
            if cert_node is not None:
                idp_cert = cert_node.text.strip().replace("\n", "").replace(" ", "")
        except Exception as e:
            print(f"Error parsing SAML metadata: {e}")

    settings = {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": f"{base_url}/saml/metadata",
            "assertionConsumerService": {
                "url": f"{base_url}/saml/acs",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        },
        "idp": {
            "entityId": idp_entity_id,
            "singleSignOnService": {
                "url": idp_sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "x509cert": idp_cert
        },
        "security": {
            "nameIdEncrypted": False,
            "authnRequestsSigned": False,
            "logoutRequestSigned": False,
            "logoutResponseSigned": False,
            "signMetadata": False,
            "wantMessagesSigned": False,
            "wantAssertionsSigned": True,
            "wantNameId": True,
            "wantNameIdEncrypted": False,
            "wantAssertionsEncrypted": False,
            "requestedAuthnContext": False,
            "wantXMLValidation": True,
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256"
        }
    }
    
    return settings

def prepare_flask_request(request):
    """
    Converts a Flask request into the dictionary format expected by python3-saml.
    """
    url_data = urlparse(request.url)
    
    # Ensure port is correctly passed if it's explicitly in the host string
    port = url_data.port
    if not port:
        port = 443 if request.scheme == 'https' else 80
        
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': port,
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy(),
        # lowercase headers are returned by python3-saml
    }
