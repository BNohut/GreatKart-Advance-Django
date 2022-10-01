import json

from django.shortcuts import render, redirect
from carts.models import CartItem
from django.contrib.auth.decorators import login_required
from .forms import OrderForm
from .models import Order, Payment, OrderProduct
import datetime
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage
# Create your views here.


def payments(request):
    """I changed Order model (order_id => null=True) for Fake Pay. Paypal isnt allowed in Turkey.
    This function throws an error, if user has more than one order which has is_ordered=False attr"""
    # body = json.loads(request.body)
    order = Order.objects.get(user=request.user, is_ordered=False)  # body['orderID'])

    # Store transaction details inside Payment model
    # payment = Payment(
    #     user=request.user,
    #     payment_id=body['transID'],
    #     payment_method=body['payment_method'],
    #     amount_paid=order.order_total,
    #     status=body['status'],
    # )
    #
    # order.payment = payment
    order.is_ordered = True
    order.save()

    # Move the cart items to Order Product Table

    cart_items = CartItem.objects.filter(user=request.user)
    for item in cart_items:
        order_product = OrderProduct()
        order_product.order_id = order.id
        # order_product.payment = payment
        order_product.user_id = request.user.id
        order_product.product_id = item.product_id
        order_product.quantity = item.quantity
        order_product.product_price = item.product.price
        order_product.ordered = True
        order_product.save()

        # Take all variation variables for each particular item in order
        cart_item = CartItem.objects.get(id=item.id)
        product_variation = cart_item.variations.all()
        order_product = OrderProduct.objects.get(id=order_product.id)
        order_product.variations.set(product_variation)
        order_product.save()

    # Reduce the quantity of the sold products
        product = cart_item.product
        product.stock -= order_product.quantity
        product.save()

    # Clear Cart
    CartItem.objects.filter(user=request.user).delete()
    # Send order recieved email to costumer
    current_site = get_current_site(request)
    user = request.user
    mail_subject = "GreatKart | Thank You!"
    message = render_to_string('orders/order_received.html', {
        'user': user,
        'order': order
    })
    to_email = user.email
    send_email = EmailMessage(mail_subject, message, to=[to_email])
    send_email.send()
    # Send order number and transaction id back to send Data method via JsonResponse

    return render(request, 'orders/payments.html')


@login_required(login_url='login')
def place_order(request, total=0, quantity=0, grand_total=0, tax=0):
    current_user = request.user
    # if cart count is less than or equal to0, them redirect back to shop
    cart_items = CartItem.objects.filter(user=current_user)
    cart_count = cart_items.count()
    if cart_count <= 0:
        return redirect('store')

    for cart_item in cart_items:
        total += (cart_item.product.price * cart_item.quantity)
        quantity += cart_item.quantity
    tax = float("{:.2f}".format((18 * total) / 100))
    grand_total = float("{:.2f}".format(total + tax))
    if request.method == 'POST':
        form = OrderForm(request.POST)
        if form.is_valid():
            # store all the billing information inside Order table
            data = Order()
            data.user = current_user
            data.first_name = form.cleaned_data['first_name']
            data.last_name = form.cleaned_data['last_name']
            data.phone = form.cleaned_data['phone']
            data.email = form.cleaned_data['email']
            data.address_line_1 = form.cleaned_data['address_line_1']
            data.address_line_2 = form.cleaned_data['address_line_2']
            data.country = form.cleaned_data['country']
            data.state = form.cleaned_data['state']
            data.city = form.cleaned_data['city']
            data.order_note = form.cleaned_data['order_note']
            data.order_total = grand_total
            data.tax = tax
            # take user ip address
            data.ip = request.META.get('REMOTE_ADDR')
            data.save()
            # Generate Order Number
            yr = int(datetime.date.today().strftime('%Y'))
            dt = int(datetime.date.today().strftime('%d'))
            mt = int(datetime.date.today().strftime('%m'))
            d = datetime.date(yr, mt, dt)

            current_date = d.strftime('%Y%m%d')
            order_number = current_date + str(data.id)
            data.order_number = order_number
            data.save()

            order = Order.objects.get(user=current_user, is_ordered=False, order_number=order_number)
            context = {
                'order': order,
                'cart_items': cart_items,
                'total': total,
                'tax': tax,
                'grand_total': grand_total
            }
            return render(request, 'orders/payments.html', context)
        else:
            return redirect('checkout')


def order_complete(request):
    return render(request, 'orders/order_complete.html')
