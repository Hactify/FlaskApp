# ***************** importing neccessary libraries ****************
import csv
import io
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
import email_validator
from gather_emails import google_dork, hunter_io, filter_alive_emails
import secrets
import smtplib
from email.mime.text import MIMEText
from ML.generatePhishingMail import generate_email
import os
from dotenv import load_dotenv

load_dotenv()                           # loading environment data
mySecretKey = secrets.token_hex(16)     # creating unique secret key


# ************************ Form classes **********************************
class CSVUploadForm(FlaskForm):
    campaign_name = StringField('Campaign Name', validators=[DataRequired()])
    csv_file = FileField('CSV File', validators=[FileRequired()])
    submit = SubmitField('Submit')

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=30)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already taken. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


# Initializing app
app = Flask(__name__)
app.config['SECRET_KEY'] = mySecretKey  # Set your secret key here
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
db = SQLAlchemy(app)
migrate = Migrate(app, db)

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# **************************** Models *****************************
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    campaigns = db.relationship('Campaign', backref='owner', lazy=True)

class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    target_domain = db.Column(db.String(150))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Email(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'))
    email_address = db.Column(db.String(150))
    first_name = db.Column(db.String(150), nullable=True)
    last_name = db.Column(db.String(150), nullable=True)
    position = db.Column(db.String(150), nullable=True)
    seniority = db.Column(db.String(150), nullable=True)
    department = db.Column(db.String(150), nullable=True)
    linkedin = db.Column(db.String(250), nullable=True)
    twitter = db.Column(db.String(250), nullable=True)
    phone_number = db.Column(db.String(50), nullable=True)
    is_alive = db.Column(db.Boolean)

with app.app_context():
    db.create_all()


# ************************ routes **************************
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)

@app.route("/")
def home():
    return render_template('home.html')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    campaigns = Campaign.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', campaigns=campaigns, email=current_user.email, current_user=current_user)

@app.route('/new_campaign', methods=['GET', 'POST'])
@login_required
def new_campaign():
    if request.method == 'POST':
        domain = request.form['domain']
        
        # Fetch emails using google_dork and hunter_io
        google_emails = google_dork(domain)
        hunter_emails = hunter_io(domain)
        
        # Combine emails into a dictionary to ensure no duplicates
        email_dict = {}
        
        # Add google_dork emails to the dictionary
        for email in google_emails:
            email_dict[email] = {
                'email_address': email,
                'first_name': None,
                'last_name': None,
                'position': None,
                'seniority': None,
                'department': None,
                'linkedin': None,
                'twitter': None,
                'phone_number': None,
                'is_alive': True
            }
        
        # Update the dictionary with hunter_io emails
        for email in hunter_emails:
            email_address = email['email_address']
            email_dict[email_address] = email
        
        # Convert the dictionary values to a list for filtering
        email_list = list(email_dict.values())
        
        # Filter alive emails
        # alive_emails = filter_alive_emails(email_list)

        # Save campaign to the database
        campaign = Campaign(name=domain, target_domain=domain, user_id=current_user.id)
        db.session.add(campaign)
        db.session.commit()

        # Save emails to the database
        for email in email_list:
            new_email = Email(
                campaign_id=campaign.id,
                email_address=email['email_address'],
                first_name=email.get('first_name'),
                last_name=email.get('last_name'),
                position=email.get('position'),
                seniority=email.get('seniority'),
                department=email.get('department'),
                linkedin=email.get('linkedin'),
                twitter=email.get('twitter'),
                phone_number=email.get('phone_number'),
                is_alive=email['is_alive']
            )
            db.session.add(new_email)
        db.session.commit()
        
        return redirect(url_for('dashboard'))
    return render_template('new_campaign.html',current_user=current_user)

# ********************************
# csv files format
# email_address,first_name,last_name,position,seniority,department,linkedin,twitter,phone_number
# ********************************
# Setup logging
import logging
logging.basicConfig(level=logging.DEBUG)

@app.route('/manual_campaign', methods=['GET', 'POST'])
@login_required
def manual_campaign():
    form = CSVUploadForm()
    if form.validate_on_submit():
        campaign_name = form.campaign_name.data
        csv_file = form.csv_file.data
        logging.debug(f"Campaign Name: {campaign_name}")
        logging.debug(f"CSV File: {csv_file}")
        
        if campaign_name:
            campaign = Campaign(name=campaign_name, user_id = current_user.id)
            db.session.add(campaign)
            db.session.commit()
            logging.debug(f"Campaign created with ID: {campaign.id}")

        if csv_file:
            try:
                stream = io.StringIO(csv_file.stream.read().decode("UTF8"), newline=None)
                csv_reader = csv.DictReader(stream)
                email_list = []

                for row in csv_reader:
                    logging.debug(f"CSV Row: {row}")
                    email = Email(
                        campaign_id=campaign.id,
                        email_address=row.get('email_address'),
                        first_name=row.get('first_name'),
                        last_name=row.get('last_name'),
                        position=row.get('position'),
                        seniority=row.get('seniority'),
                        department=row.get('department'),
                        linkedin=row.get('linkedin'),
                        twitter=row.get('twitter'),
                        phone_number=row.get('phone_number'),
                        is_alive=True
                    )
                    db.session.add(email)
                    email_list.append(email.email_address)
                db.session.commit()

                logging.debug(f"Emails added: {email_list}")
                flash(f"Campaign '{campaign_name}' created with uploaded emails.", 'info')
                return redirect(url_for('dashboard'))

            except Exception as e:
                logging.error(f"Error processing CSV file: {e}")
                flash(f"Error processing CSV file: {str(e)}", 'danger')
                return redirect(url_for('manual_campaign'))

    return render_template('new_manualCampaign.html', form=form, current_user=current_user)

@app.route('/view_campaign/<int:campaign_id>')
@login_required
def view_campaign(campaign_id):
    campaign = Campaign.query.get(campaign_id)
    emails = Email.query.filter_by(campaign_id=campaign_id).all()
    return render_template('view_campaign.html', campaign=campaign, emails=emails, current_user=current_user)


# prompt = "Dear user,"
# print(generate_email(prompt))

# Define a route for generating emails
@app.route('/generate-email', methods=['POST'])
def generate_email_route():
    data = request.json
    prompt = data.get('prompt', 'Dear user,')
    
    email_text = generate_email(prompt)
    
    return jsonify({'email_text': email_text})



def send_email(subject, body, to_email):
    from_email = os.getenv('EMAIL_USER')
    password = os.getenv('APP_PASS') # create app password from the gmail account you want to send the mail

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = from_email
    msg['To'] = to_email

    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login(from_email, password)
        server.sendmail(from_email, to_email, msg.as_string())

# # Usage
# subject = "Important Update"
# body = generate_email(prompt)
# to_email = "to@gmail.com"
# send_email(subject, body, to_email)


@app.route('/send_email', methods=['GET','POST'])
def send_email_route():
    if request.method == "POST":
        subject = "Important Update"
        body = generate_email("Dear User")
        to_email = request.form['to_email']
        try:
            send_email(subject, body, to_email)
            flash('Email sent successfully!', 'success')
        except Exception as e:
            flash(f'Failed to send email: {e}', 'danger')

        return redirect(url_for('dashboard'))
    
    return render_template('email_form.html', current_user=current_user)

@app.route('/send_single_email/<int:user_id>', methods=['POST'])
def send_single_email(user_id):
    email = Email.query.filter_by(id=user_id, is_alive=True).first()
    if email:
        subject = "Important Update"
        to_email = email.email_address
        if (email.first_name and email.last_name and email.position):
            body = generate_email(f"Dear {email.first_name} {email.last_name}, {email.position}")
        elif (email.first_name and email.last_name and not email.position):
            body = generate_email(f"Dear {email.first_name} {email.last_name}")
        else:
            body = generate_email(f"Dear User")

        try:
            send_email(subject, body, to_email)
            flash(f"Email sent to {to_email}", 'success')
        except Exception as e:
            flash(f"Failed to send email: {e}", 'danger')
    else:
        flash("User ID not found or email is not alive", "danger")

    return redirect(url_for('dashboard'))

@app.route('/send_bulk_email/<int:campaign_id>', methods=['POST'])
def send_bulk_email(campaign_id):
    emails = Email.query.filter_by(campaign_id=campaign_id, is_alive=True).all()
    if not emails:
        return "No emails found for this campaign or emails are not alive", 404
    
    subject = "Important Update"
    errors = []
    
    for email in emails:
        if (email.first_name and email.last_name and email.position):
            body = generate_email(f"Dear {email.first_name} {email.last_name}, {email.position}")
        elif (email.first_name and email.last_name and not email.position):
            body = generate_email(f"Dear {email.first_name} {email.last_name}")
        else:
            body = generate_email(f"Dear User")
        try:
            send_email(subject, body, email.email_address)
        except Exception as e:
            errors.append((email.email_address, str(e)))
    
    if errors:
        flash(f"Failed to send emails to: {errors}", 'danger')
    else:
        flash("Bulk emails sent successfully!", 'success')

    return redirect(url_for('dashboard'))


# running our flask app
if __name__ == '__main__':
    app.run(debug=True)
