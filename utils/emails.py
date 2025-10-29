import requests

from email.mime.image import MIMEImage
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags


def render_email(
    name: str,
    texts: list[str],
    cta_link: str,
    cta_text: str,
    key_items: dict = {},
    extra_image: bool = False,
) -> tuple[str, str]:
    """Send an email to the user to activate their account.

    Args:
        name (str): user name
        texts (list[str]): list of strings to display above the CTA
        cta_link (str): link to the CTA
        cta_text (str): text to display on the CTA
        key_items (dict): list items like key-value pairs to display in the email
        extra_image (bool): if an extra image is provided in the email

    Returns:
        tuple[str, str]: html_message, plain_message

    """

    # Rende html content
    context = {
        "name": name,
        "texts": texts,
        "cta_link": cta_link,
        "cta_text": cta_text,
        "key_items": key_items,
        "extra_image": extra_image,
        "SITE_BRAND": settings.SITE_BRAND,
        "EMAIL_SUPPORT": settings.EMAIL_SUPPORT,
    }

    html_message = render_to_string("users/base_email.html", context)
    plain_message = strip_tags(html_message)

    return html_message, plain_message


def send_email(
    subject: str,
    name: str,
    texts: list[str],
    cta_link: str,
    cta_text: str,
    to_email: str,
    key_items: dict = {},
    image_src: str = "",
):
    """Send an email to the user to activate their account.

    Args:
        subject (str): email subject (title
        name (str): user name
        texts (list[str]): list of strings to display above the CTA
        cta_link (str): link to the CTA
        cta_text (str): text to display on the CTA
        to_email (str): email to send the email to
        key_items (dict): list items like key-value pairs to display in the email
        image_src (str): extra image source to display in the email
    """
    import os
    from django.conf import settings

    # Get rendered html
    html_message, plain_message = render_email(
        name, texts, cta_link, cta_text, key_items, extra_image=image_src != ""
    )

    # Add html and plain text to the email
    message = EmailMultiAlternatives(
        subject, plain_message, settings.EMAIL_HOST_USER, [to_email]
    )
    message.attach_alternative(html_message, "text/html")

    # Attach logo file - using direct file path approach
    logo_attached = False
    try:
        
        # Direct path to the logo file
        image_name = 'banner.webp'
        logo_file_path = os.path.join(
            settings.BASE_DIR, 'core', 'static', 'core', 'imgs', image_name
        )
        
        if os.path.exists(logo_file_path):
            with open(logo_file_path, 'rb') as logo_file:
                logo_data = logo_file.read()
            
            # Create MIME image with proper headers
            logo = MIMEImage(logo_data)
            logo.add_header('Content-ID', '<logo>')
            logo.add_header('Content-Disposition', 'inline', filename=image_name)
            
            message.attach(logo)
            logo_attached = True
            
    except Exception:
        import traceback
        traceback.print_exc()
    
    # If logo couldn't be attached, provide a fallback
    if not logo_attached:
        # Create a simple blue rectangle with "LOGO" text as fallback
        fallback_svg = '''
        <svg width="200" height="50" viewBox="0 0 200 50" fill="none"
             xmlns="http://www.w3.org/2000/svg">
            <rect width="200" height="50" fill="#007bff"/>
            <text x="100" y="30" font-family="Arial" font-size="14"
                  fill="white" text-anchor="middle">LOGO</text>
        </svg>
        '''
        import base64
        fallback_b64 = base64.b64encode(fallback_svg.encode()).decode()
        
        # Replace cid:logo with base64 fallback
        html_message = html_message.replace(
            'src="cid:logo"',
            f'src="data:image/svg+xml;base64,{fallback_b64}"'
        )
        
        # Update the message with modified HTML
        message.alternatives = []
        message.attach_alternative(html_message, "text/html")

    if image_src:
        # Download image in a temp folder
        image_base = image_src.split("/")[-1]
        image_temp_folder = os.path.join(settings.BASE_DIR, "media", "temp")
        image_temp_path = f"{image_temp_folder}/{image_base}"
        os.makedirs(image_temp_folder, exist_ok=True)

        try:
            res = requests.get(image_src)
        except Exception:
            pass
        else:
            with open(image_temp_path, "wb") as img:
                img.write(res.content)

            # Attach an image if provided
            with open(image_temp_path, "rb") as img:
                img_data = img.read()
            image = MIMEImage(img_data, name=image_base)
            image.add_header("Content-ID", "<image1>")
            message.attach(image)

    message.send()


def test_email_with_logo(to_email: str):
    """Test function to send an email with embedded logo.
    
    Args:
        to_email (str): email address to send test email to
    """
    send_email(
        subject="Test Email with Logo",
        name="Test User",
        texts=[
            "This is a test email to verify that the logo is properly embedded.",
            "If you can see the logo above, the embedding is working correctly!"
        ],
        cta_link="https://example.com",
        cta_text="Test Button",
        to_email=to_email,
        key_items={
            "Test Key": "Test Value",
            "Status": "Working"
        }
    )