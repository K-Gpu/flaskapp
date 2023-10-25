from flask import Flask,render_template, redirect, request, url_for
from flask_login import (
    current_user,
    login_user,
    logout_user
)
import base64
from flask_dance.contrib.github import github

from apps import db, login_manager
from flask_login import current_user, login_required
from apps.authentication import blueprint
from apps.authentication.forms import LoginForm, CreateAccountForm
from apps.authentication.models import User,Solos,Event,Institution,Parcel,Profile
from apps.authentication.util import hash_pass



from apps.authentication.util import verify_pass
from flask_mail import Mail, Message

from random import *
import time
import secrets

app=Flask(__name__)


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'kngetich@kabarak.ac.ke'
app.config['MAIL_PASSWORD'] = 'ykxbcpfbmvijlmqv'

Mail=Mail(app)



@blueprint.route('/')
def route_default():
    return redirect(url_for('authentication_blueprint.login'))

# Login & Registration

@blueprint.route("/github")
def login_github():
    """ Github login """
    if not github.authorized:
        return redirect(url_for("github.login"))

    res = github.get("/user")
    return redirect(url_for('home_blueprint.index'))

@blueprint.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm(request.form)
    if 'login' in request.form:

        # read form data
        user_id  = request.form['username'] # we can have here username OR email
        password = request.form['password']

        # Locate user
        user = User.find_by_username(user_id)

        # if user not found
        if not user:

            user = User.find_by_email(user_id)

            if not user:
                return render_template( 'accounts/login.html',
                                        msg='Unknown User or Email',
                                        form=login_form)

        # Check the password
        if verify_pass(password, user.password):

            login_user(user)
            return redirect(url_for('authentication_blueprint.route_default'))

        # Something (user or pass) is not ok
        return render_template('accounts/login.html',
                               msg='Wrong user or password',
                               form=login_form)

    if not current_user.is_authenticated:
        return render_template('accounts/login.html',
                               form=login_form)
    else:
        record = User.query.filter_by(is_verified=1).first()
        if record:
            return redirect(url_for('authentication_blueprint.explore'))
        else:
            msgs="Please verify your email before logging in."
            return render_template('home/email_verify.html',msgs=msgs)
    


@blueprint.route('/register', methods=['GET', 'POST'])
def register():
    create_account_form = CreateAccountForm(request.form)
    if 'register' in request.form:

        username = request.form['username']
        email = request.form['email']
        is_verified=0
        otp=str(secrets.randbelow(1000000)).zfill(6)
        otp_secret=otp
        verification_sent_at = int(time.time())

        # Check usename exists
        user = User.query.filter_by(username=username).first()
        if user:
            return render_template('accounts/register.html',
                                   msg='Username already registered',
                                   success=False,
                                   form=create_account_form)

        # Check email exists
        user = User.query.filter_by(email=email).first()
        if user:
            return render_template('accounts/register.html',
                                   msg='Email already registered',
                                   success=False,
                                   form=create_account_form)

        # else we can create the user
        send_verification(email, otp)
        user = User(**request.form,verification_sent_at=verification_sent_at,is_verified=is_verified,otp_secret=otp_secret)
        db.session.add(user)
        db.session.commit()

        # Delete user from session
        logout_user()

        return render_template('home/email_verify.html',
                               msg='User created successfully.',
                               success=True,
                               form=create_account_form)

    else:
        return render_template('accounts/register.html', form=create_account_form)


def send_verification(email, otp):
    subject = 'Email Verification code'
    msg = Message(subject=subject, sender='kngetich@kabarak.ac.ke', recipients=[email])
    msg.body = f'Your verification code is: {otp}'
    try:
        Mail.send(msg)
    except Exception as e:
        print("Error sending email:", e)


@blueprint.route('/email_verification',methods=['POST','GET'])
def email_verify():
    if request.method == 'POST':
        user_otp = request.form['otp']
        user=User.query.filter_by(otp_secret=user_otp).first()
        if user is not None:
            is_verified = int(user.otp_secret)  
            if is_verified == 1:
                success="Email has already been verified. You can now login."
                return redirect(url_for('authentication_blueprint.login'),success=success)
            else:
                verification_sent_at = user.verification_sent_at
                current_timestamp = int(time.time())
                expiration_time =24 * 60 * 60

                if current_timestamp - verification_sent_at > expiration_time:
                    user=User.query.filter_by(otp_secret=user_otp).first()
                    try:
                        db.session.add(new_profile)
                        db.session.commit()
                    except Exception as e:
                        print("Error:", str(e))
                        db.session.rollback()
                    msg="Verification email has expired. Account  deleted."
                    return redirect(url_for('authentication_blueprint.register'))

                record=User.query.filter_by(otp_secret=user_otp).first()
                is_verified = 1

                if record is not None:
                    record.is_verified = is_verified
                    try:
                        db.session.commit()
                        flash('Email verified successfully now can login.','success')
                        return redirect(url_for('home_blueprint.login'))
                    except Exception as e:
                        print("Error:", str(e))
                        db.session.rollback()

                    
        else:
            msg="You have entered an invalid code."
            return render_template('home/email_verify.html',msg=msg)
    return render_template('home/email_verify.html')



@blueprint.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('authentication_blueprint.login')) 

# Errors

@login_manager.unauthorized_handler
def unauthorized_handler():
    return render_template('home/page-403.html'), 403


@blueprint.errorhandler(403)
def access_forbidden(error):
    return render_template('home/page-403.html'), 403


@blueprint.errorhandler(404)
def not_found_error(error):
    return render_template('home/page-404.html'), 404


@blueprint.errorhandler(500)
def internal_error(error):
    return render_template('home/page-500.html'), 500


@blueprint.route('/soloservice', methods=['GET', 'POST'])
@login_required
def trip():
    if request.method == 'POST':
        pick_up = request.form['Location']
        destination = request.form['destination']
        seats = int(request.form['seats'])
        date = request.form['TravelDate']
        time = request.form['Time']
        amount = int(request.form['amount'])

        new_booking = Solos(
            username=current_user.username,
            Pick_Up=pick_up,
            Destination=destination,
            Seats=seats,
            Date=date,
            Time=time,
            Amount=amount
        )

        try:
            new_booking.save()  
            return redirect(url_for('home_blueprint.index'))  
        except Exception as e:
            
            print("Error:", str(e))

    return render_template('home/solo-travel.html')  


@blueprint.route('/eventservice', methods=['GET', 'POST'])
@login_required
def event():
    if request.method == 'POST':
        event_type = request.form['event_type']
        location = request.form['location']
        destination = request.form['destination']
        constituency= request.form['constituency']
        town =request.form['town']
        number_pass = int(request.form['matatu'])
        date = request.form['date']
        time = request.form['time']
        amount = int(request.form['amount'])

        new_booking = Event(
            username=current_user.username,
            location=location,
            Destination=destination,
            constituency=constituency,
            town=town,
            number_pass=number_pass,
            Date=date,
            Time=time,
            Amount=amount
        )

        try:
            new_booking.save()  
            return redirect(url_for('home_blueprint.index'))  
        except Exception as e:
            
            print("Error:", str(e))

    return render_template('home/event-travel.html')  



@blueprint.route('/institutionservice', methods=['GET', 'POST'])
@login_required
def institution():
    if request.method == 'POST':
        pick_up = request.form['location']
        destination = request.form['destination']
        seats = int(request.form['seats'])
        date = request.form['date']
        time = request.form['time']
        amount = int(request.form['amount'])

        new_booking = Institution(
            username=current_user.username,
            Pick_Up=pick_up,
            Destination=destination,
            Seats=seats,
            Date=date,
            Time=time,
            Amount=amount
        )

        try:
            new_booking.save()  
            return redirect(url_for('home_blueprint.index'))  
        except Exception as e:
            
            print("Error:", str(e))

    return render_template('home/student-travel.html')  



@blueprint.route('/parcelservice', methods=['GET', 'POST'])
@login_required
def parcel():
    if request.method == 'POST':
        pick_up = request.form['location']
        destination = request.form['destination']
        photo = request.files['photo'].read()
        amount = int(request.form['amount'])

        new_booking = Parcel(
            username=current_user.username,
            Pick_Up=pick_up,
            Destination=destination,
            photo=photo,
            Amount=amount
        )

        try:
            new_booking.save()  
            return redirect(url_for('home_blueprint.index'))  
        except Exception as e:
            
            print("Error:", str(e))

    return render_template('home/parcel-transport.html')  



@blueprint.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        fname = request.form['fname']
        lname = request.form['lname']
        address = request.form['address']
        bio = request.form['bio']
        photo = request.files['photo'].read()
        phone=request.form['phone']

        record = Profile.query.filter_by(username=current_user.username).first()

        if record is not None:
            # Update the existing user profile
            record.username = current_user.username
            record.email = current_user.email
            record.firstName = fname
            record.lastName = lname
            record.address = address
            record.bio = bio
            record.image = photo
            record.phone=phone

            try:
                db.session.commit()
            except Exception as e:
                print("Error:", str(e))
                db.session.rollback()
        else:
            # Create a new user profile
            new_profile = Profile(
                username=current_user.username,
                email=current_user.email,
                firstName=fname,
                lastName=lname,
                address=address,
                image=photo,
                bio=bio,
                phone=phone
            )

            try:
                db.session.add(new_profile)
                db.session.commit()
            except Exception as e:
                print("Error:", str(e))
                db.session.rollback()

    # Retrieve the updated or newly created profile record
    data = Profile.query.filter_by(username=current_user.username).first()
    if data:
        image=data.image
        image_base64=base64.b64encode(image).decode('utf-8')
        if data.image:
            return render_template('home/profile.html', data=data,image_base64=image_base64)
        
    return render_template('home/profile.html', data=data)



import base64

@blueprint.route('/index')
@login_required
def index():
    user_bookings = Solos.query.filter_by(username=current_user.username).all()
    data = Institution.query.filter_by(username=current_user.username).all()
    event_info = Event.query.filter_by(username=current_user.username).all()
    parcel_info = Parcel.query.filter_by(username=current_user.username).all()

    all_user_bookings = Solos.query.all()
    count = len(all_user_bookings)
    all_data = Institution.query.all()
    count2 = len(all_data)
    all_event_info = Event.query.all()
    count3 = len(all_event_info)
    all_parcel_info = Parcel.query.all()
    count4 = len(all_parcel_info)

    count = count + count2 + count3 + count4
    per_cent = int(count / 50 * 100)

    modified_data = []
    for item in parcel_info:
        image_data = item.photo
        image_data_base64 = base64.b64encode(image_data).decode('utf-8')
        modified_item = item.__dict__.copy()  # Create a copy of the object's attributes
        modified_item['photo'] = image_data_base64  # Modify the 'photo' attribute
        modified_data.append(modified_item)


    all_modified_data = []
    for item in all_parcel_info:
        image_data = item.photo
        image_data_base64 = base64.b64encode(image_data).decode('utf-8')
        modified_item = item.__dict__.copy()  
        modified_item['photo'] = image_data_base64  
        all_modified_data.append(modified_item)


    return render_template('home/index.html', count=count, per_cent=per_cent, bookings=user_bookings,
                           institution=data, event_info=event_info, parcel_info=modified_data, all_data=all_data,
                           all_event_info=all_event_info, all_parcel_info=all_modified_data,
                           all_user_bookings=all_user_bookings)

@blueprint.route('/home')
@login_required
def explore():
    return render_template('home/explore.html')



@blueprint.route('/status/<id>/<table>',methods=['POST','GET'])
@login_required
def Status(id,table):
    if request.method == 'POST':
        status = request.form['status']
        
        if table=="solo":
            record = Solos.query.filter_by(id=id).first()

            if record is not None:
                record.status = status
                
                try:
                    db.session.commit()
                    return redirect(url_for('home_blueprint.index'))
                except Exception as e:
                    print("Error:", str(e))
                    db.session.rollback()
        elif table=="institution":
            record = Institution.query.filter_by(id=id).first()

            if record is not None:
                record.status = status
                
                try:
                    db.session.commit()
                    return redirect(url_for('home_blueprint.index'))
                except Exception as e:
                    print("Error:", str(e))
                    db.session.rollback()
        
        elif table=="event":
            record = Event.query.filter_by(id=id).first()

            if record is not None:
                record.status = status
                
                try:
                    db.session.commit()
                    return redirect(url_for('home_blueprint.index'))
                except Exception as e:
                    print("Error:", str(e))
                    db.session.rollback()

        elif table=="parcel":
            record = Parcel.query.filter_by(id=id).first()

            if record is not None:
                record.status = status
                
                try:
                    db.session.commit()
                    return redirect(url_for('home_blueprint.index'))
                except Exception as e:
                    print("Error:", str(e))
                    db.session.rollback()
    return render_template('home/status.html')

@blueprint.route('/pay/<id>/<table>',methods=['POST','GET'])
@login_required
def Payment(id,table):
    if table=="solo":
        record = Solos.query.filter_by(id=id).first()
        data= Profile.query.filter_by(username=current_user.username).first()
    
    elif table=="event":
        record = Event.query.filter_by(id=id).first()
        data= Profile.query.filter_by(username=current_user.username).first()

    elif table=="institution":
        record = Institution.query.filter_by(id=id).first()
        data= Profile.query.filter_by(username=current_user.username).first()

    elif table=="parcel":
        record = Parcel.query.filter_by(id=id).first()
        data= Profile.query.filter_by(username=current_user.username).first()

    return render_template('home/pay.html',record=record,data=data)




@blueprint.route('/forgot',methods=['POST','GET'])
def forgot():
    if request.method=='POST':
            email=request.form['email']
            result=User.query.filter_by(email=email).first()
            if result:
                token=secrets.token_hex(32)
                reset_link=url_for('authentication_blueprint.reset',token=token,_external=True)
                msg=Message(subject='Password Reset Request',sender='kngetich@kabarak.ac.ke',recipients=[email])
                msg.body=f'Click the following link to reset your password:{reset_link}'
                Mail.send(msg)
                reset_sent_at = int(time.time())
                record=User.query.filter_by(email=email).first()
                record.token=token
                record.reset_sent_at=reset_sent_at
                try:
                    db.session.commit()
                except Exception as e:
                    print("Error:", str(e))
                    db.session.rollback()
                success="Reset link send to your email"
                return render_template('home/forgot.html',success=success)
            else:
                msg="We can't find your email in our system"
                return render_template('home/forgot.html',msg=msg)
    return render_template('home/forgot.html')



@blueprint.route('/reset',methods=['POST','GET'])
def reset():
    if request.method=='POST':
        password=request.form['password']
        re_password=request.form['confirm']
        token = request.args.get('token') 
        if password != re_password:
            msg="Passwords do not match"
            return redirect(url_for('authentication_blueprint.reset',msg=msg,token=token))
        
        result=User.query.filter_by(token=token).first()
        if result:
            reset_sent_at = result.reset_sent_at
            user_id=result.id

        
            current_timestamp = int(time.time())
            expiration_time = 15 * 60
            if current_timestamp - reset_sent_at > expiration_time:
                msg="The token has expired token"
                return render_template('home/forgot.html',msg=msg)

            hashed_password=hash_pass(password)
            record=User.query.filter_by(id=user_id).first()
            if record:
                record.password=hashed_password
                record.token="token"
                try:
                    db.session.commit()
                except Exception as e:
                    print("Error:", str(e))
                    db.session.rollback()
                success="Password reset successfully"
                return redirect(url_for('authentication_blueprint.login',success=success))
                
        else:
            msg="Invalid or expired token"
            return redirect(url_for('authentication_blueprint.forgot',msg=msg)) 
    return render_template('home/reset.html')