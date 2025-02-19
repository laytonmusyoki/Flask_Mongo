from flask import Flask,render_template,redirect,url_for,request,session,flash
from flask_pymongo import PyMongo
from flask_mail import Mail,Message
import re
import secrets
import bcrypt
import time

app = Flask(__name__)

app.secret_key = secrets.token_hex(16)

app.config["MONGO_URI"] = "mongodb://localhost:27017/flaskMongo"
mongo = PyMongo(app)


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'laytonmatheka7@gmail.com'
app.config['MAIL_PASSWORD'] = 'qamfnggyldkpbhje'

mail = Mail(app)


@app.route('/home')
def home():
    return render_template('index.html')


# register function
@app.route('/register',methods=['POST','GET'])
def register():
    if 'user_id' in session:
        flash("You are already logged in","error")
        return redirect(url_for('contact'))
    if request.method=='POST':
        username=request.form['username']
        email=request.form['email']
        password=request.form['password']
        confirm_password=request.form['confirm_password']
        if username=='' or email=='' or password=='' or confirm_password=='':
            flash('All fields are required','error')
            return render_template('register.html',username=username,email=email,password=password,confirm_password=confirm_password)
        elif len(password) < 8:
            flash("password must be more than 8 characters!",'error')
            return render_template('register.html',username=username,email=email,password=password,confirm_password=confirm_password)
        elif password !=confirm_password:
            flash("password do not match",'error')
            return render_template('register.html',username=username,email=email,password=password,confirm_password=confirm_password)
        elif not re.search("[a-z]", password):
            flash("password must have small letters!",'error')
            return render_template('register.html',username=username,email=email,password=password,confirm_password=confirm_password)
        elif not re.search("[A-Z]", password):
            flash("password must have capital letters!",'error')
            return render_template('register.html',username=username,email=email,password=password,confirm_password=confirm_password)
        elif not re.search("[_@&$!]+", password):
            flash("Password must contain special characters!",'error')
            return render_template('register.html',username=username,email=email,password=password,confirm_password=confirm_password)
        else:
            user = mongo.db.users.find_one({"username":username})
            if user:
                flash('User with that username already exist','error')
                return render_template('register.html',username=username,email=email,password=password,confirm_password=confirm_password)
            else:
                hashed_password=bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())
                mongo.db.users.insert_one({"username":username,"email":email,"password":hashed_password,"role":"user","token":"0","reset_sent_at":"0"})
                flash('Account created successfully','success')
                return redirect(url_for('login'))
    return render_template('register.html')


# login route
@app.route('/',methods=['POST','GET'])
def login():
    if 'user_id' in session:
        flash("You are already logged in","error")
        return redirect(url_for('contact'))
    if request.method=="POST":
        username=request.form['username']
        password=request.form['password']
        if username=="" or password=="":
            flash("All fields are required","error")
            return render_template('login.html',username=username,password=password)
        else:
            user_data = mongo.db.users.find_one({'username': username})
            if user_data:
                if bcrypt.checkpw(password.encode('utf-8'),user_data['password']):
                    session['user_id']=user_data['_id']
                    session['role']=user_data['role']
                    session['username']=user_data['username']
                    if session['role'] =="admin":
                        return redirect(url_for('admin'))
                    return redirect(url_for('contact'))
                else:
                    flash("Password is incorrect","error")
                    return render_template('login.html',username=username,password=password)
            else:
                flash("Username does not exist in our account","error")
                return render_template('login.html',username=username,password=password)
    return render_template('login.html')


@app.route('/forgot',methods=['POST','GET'])
def forgot():
    if 'user_id' in session:
        flash("You are already logged in","error")
        return redirect(url_for('contact'))
    if request.method=="POST":
        email=request.form['email']
        user_data = mongo.db.users.find_one({'email': email})
        if user_data:
            token=secrets.token_hex(32)
            reset_link=url_for('reset',token=token,_external=True)
            try:
                msg=Message(subject='Password Reset Request',sender='laytonmatheka7@gmail.com',recipients=[email])
                msg.body=f'Click the following link to reset your password:{reset_link}'
                mail.send(msg)
            except Exception as e:
                flash("An error occured while sending email","error")
                return render_template('forgot.html',email=email)
            reset_sent_at = int(time.time())
            mongo.db.users.update_one({"email":email},{"$set":{"token":token,"reset_sent_at":reset_sent_at}})
            flash("Reset link send to your email address","success")
            return redirect(url_for('login'))
        else:
            flash("Email does not exist in our account","error")
            return render_template('forgot.html',email=email)
    return render_template('forgot.html')


@app.route('/reset',methods=['POST','GET'])
def reset():
    if 'user_id' in session:
        flash("You are already logged in","error")
        return redirect(url_for('contact'))
    if request.method=='POST':
        password=request.form['password']
        confirm_password=request.form['confirm_password']
        token = request.args.get('token') 
        if password=="" or confirm_password=="":
            flash("All fields are required","error")
            return render_template('reset.html',password=password,confirm_password=confirm_password)
        elif len(password) < 8:
            flash("password must be more than 8 characters!",'error')
            return render_template('reset.html',password=password,confirm_password=confirm_password)
        elif password !=confirm_password:
            flash("password do not match",'error')
            return render_template('reset.html',password=password,confirm_password=confirm_password)
        elif not re.search("[a-z]", password):
            flash("password must have small letters!",'error')
            return render_template('reset.html',password=password,confirm_password=confirm_password)
        elif not re.search("[A-Z]", password):
            flash("password must have capital letters!",'error')
            return render_template('reset.html',password=password,confirm_password=confirm_password)
        elif not re.search("[_@$!]+", password):
            flash("Password must contain special characters!",'error')
            return render_template('reset.html',password=password,confirm_password=confirm_password)
        else:
            user_data = mongo.db.users.find_one({'token': token})
            if user_data:
                current_time = int(time.time())
                reset_sent_at=user_data['reset_sent_at']
                expiration_time=15 * 60
                if current_time - reset_sent_at > expiration_time :
                    flash("Token has expired","error")
                    return redirect(url_for('forgot'))
                else:
                    hashed_password=bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())
                    mongo.db.users.update_one({"token":token},{"$set":{"password":hashed_password,"token":"0","reset_sent_at":"0"}})
                    flash("Password reset successfully","success")
                    return redirect(url_for('login'))
            else:
                flash("Invalid token","error")
                return render_template('reset.html',password=password,confirm_password=confirm_password)
    return render_template('reset.html')


@app.route('/contact', methods=['POST', 'GET'])
def contact():
    if 'user_id' not in session:
        flash("Please login to access this page", "error")
        return redirect(url_for('login'))
    user_id = session.get('user_id')
    existing_contact = None

    if user_id:
        existing_contact = mongo.db.contact.find_one({"user_id": user_id})

    if request.method == "POST":
        phone = request.form.get('phone')  
        email = request.form.get('email')
        address = request.form.get('address')
        reg_no = request.form.get('reg_no')

        if not phone or not email or not address or not reg_no:
            flash("All fields are required", "error")
            return render_template('contact.html', existing_contact=existing_contact, phone=phone, email=email, address=address, reg_no=reg_no)

        contact_data = {
            "user_id": user_id,
            "phone": phone,
            "email": email,
            "address": address,
            "reg_no": reg_no
        }

        if existing_contact:
            mongo.db.contact.update_one(
                {"user_id": user_id},
                {"$set": contact_data}
            )
            flash("Contact info updated successfully", "success")
        else:
            mongo.db.contact.insert_one(contact_data)
            flash("Contact info added successfully", "success")

        return redirect(url_for('contact'))

    return render_template('contact.html', existing_contact=existing_contact)


@app.route('/admin')
def admin():
    if 'user_id' not in session:
        flash("Please login to access this page", "error")
        return redirect(url_for('login'))
    contacts=list(mongo.db.contact.find())
    return render_template('admin.html',contacts=contacts)


@app.route('/role')
def changeRole():
    admin=mongo.db.users.update_one({"username":"Layton"},{"$set":{"role":"admin"}})
    return "Role changed successfully"

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
    
    
