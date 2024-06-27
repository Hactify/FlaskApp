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
import torch
import pandas as pd
from transformers import GPT2Tokenizer, GPT2LMHeadModel
import random
import smtplib
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv

load_dotenv()


mySecretKey = secrets.token_hex(16)

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


app = Flask(__name__)
app.config['SECRET_KEY'] = mySecretKey  # Set your secret key here
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
db = SQLAlchemy(app)
migrate = Migrate(app, db)

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    target_domain = db.Column(db.String(150))

class Email(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'))
    email_address = db.Column(db.String(150))
    is_alive = db.Column(db.Boolean)

with app.app_context():
    db.create_all()

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
    campaigns = Campaign.query.all()
    return render_template('dashboard.html', campaigns=campaigns, email=current_user.email)

@app.route('/new_campaign', methods=['GET', 'POST'])
@login_required
def new_campaign():
    if request.method == 'POST':
        domain = request.form['domain']
        emails = google_dork(domain)
        emails.update(hunter_io(domain))
        alive_emails = filter_alive_emails(emails)

        # Save campaign and emails to database
        campaign = Campaign(name=domain, target_domain=domain)
        db.session.add(campaign)
        db.session.commit()

        for email in alive_emails:
            db.session.add(Email(campaign_id=campaign.id, email_address=email, is_alive=True))
        db.session.commit()
        
        return redirect(url_for('dashboard'))
    return render_template('new_campaign.html')

@app.route('/manual_campaign', methods=['GET', 'POST'])
@login_required
def manual_campaign():
    form = CSVUploadForm()
    if form.validate_on_submit():
        campaign_name = form.campaign_name.data
        csv_file = form.csv_file.data
        if campaign_name:
            campaign = Campaign(name=campaign_name)
            db.session.add(campaign)
            db.session.commit()

        if csv_file:
            # Process the uploaded CSV file
            email_list = []
            try:
                stream = io.StringIO(csv_file.stream.read().decode("UTF8"), newline=None)
                csv_reader = csv.reader(stream)
                for row in csv_reader:
                    email_list.extend(row)  # Assuming one email per row

                for email in email_list:
                    db.session.add(Email(campaign_id=campaign.id, email_address=email, is_alive=True))
                db.session.commit()

            except Exception as e:
                flash(f"Error processing CSV file: {str(e)}", 'danger')
                return redirect(url_for('new_campaign'))

            # Display the emails (for demonstration)
            flash(f"Uploaded emails: {email_list}", 'info')
            return redirect(url_for('dashboard'))

    return render_template('new_manualCampaign.html', form=form)

@app.route('/view_campaign/<int:campaign_id>')
@login_required
def view_campaign(campaign_id):
    campaign = Campaign.query.get(campaign_id)
    emails = Email.query.filter_by(campaign_id=campaign_id).all()
    return render_template('view_campaign.html', campaign=campaign, emails=emails)


links_df=pd.read_csv("phishing_links.csv")
links=links_df['url'].tolist()

# Load the tokenizer and model
tokenizer = GPT2Tokenizer.from_pretrained("phishing_email_generator")
model = GPT2LMHeadModel.from_pretrained("phishing_email_generator")

# Move the model to the appropriate device
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
model.to(device)

def generate_email(prompt):
    inputs = tokenizer.encode(prompt, return_tensors='pt', padding=True, truncation=True)
    inputs = inputs.to(device)  # Move inputs to the same device as the model
    
    outputs = model.generate(
        inputs,
        max_length=200,
        num_return_sequences=1,
        pad_token_id=tokenizer.eos_token_id,
        do_sample=True,
        temperature=0.7,  # Controls the randomness of predictions (lower = more deterministic)
        top_k=50,  # Limits the sampling pool to top_k tokens
        top_p=0.9  # Nucleus sampling: samples from the smallest possible set of tokens whose cumulative probability exceeds top_p
    )
    
    generated_text = tokenizer.decode(outputs[0], skip_special_tokens=True)
    
    # Select a random link from the dataset (assuming links list is loaded)
    random_link = random.choice(links)
    
    # Append the random link and "Thank you" to the generated email
    final_email = f"{generated_text}\n\n{random_link}\n\nThank you."
    
    return final_email

prompt = "Dear user,"
print(generate_email(prompt))

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
        body = generate_email(prompt)
        to_email = request.form['to_email']
        try:
            send_email(subject, body, to_email)
            flash('Email sent successfully!', 'success')
        except Exception as e:
            flash(f'Failed to send email: {e}', 'danger')

        return redirect(url_for('dashboard'))
    
    return render_template('email_form.html')

@app.route('/send_single_email/<int:user_id>', methods=['POST'])
def send_single_email(user_id):
    email = Email.query.filter_by(id=user_id, is_alive=True).first()
    if email:
        subject = "Important Update"
        to_email = email.email_address
        body = generate_email(f"Dear {email.email_address}")
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
        body = generate_email(f"Dear {email.email_address}")
        try:
            send_email(subject, body, email.email_address)
        except Exception as e:
            errors.append((email.email_address, str(e)))
    
    if errors:
        flash(f"Failed to send emails to: {errors}", 'danger')
    else:
        flash("Bulk emails sent successfully!", 'success')

    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
