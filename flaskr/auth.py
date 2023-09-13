import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')



@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        Email = request.form['Email']
        password = request.form['password']
        verificarcontraseña = request.form['verificarContraseña']

        db = get_db()
        error = None

        if not username:
            error = 'Se requiere usuario'

        elif not Email:
            error = 'Por favor, revise de nuevo su correo electronico.'
        
        elif not password:
            error = 'Se requiere contraseña.'
        
        elif not verificarcontraseña == password:
           error = 'Contraseña incorrecta, por favor revise de nuevo'

        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (username, password, Email) VALUES (?, ?, ?)",
                    (username, generate_password_hash(password), Email),
                )
                db.commit()
            except db.IntegrityError:
                error = f"el usurio {username} se encuentra registrado."
            else:
                return redirect(url_for("auth.login"))

        flash(error)

    return render_template('auth/register.html')



@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        

        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Nombre de usuario incorrecto, por favor reviselo'
        elif not check_password_hash(user['password'], password):
            error = 'Contraseña incorrecta, por favor reviselo'

       

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')



@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()



@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))



def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view

@bp.route('/modificacionEmail', methods=('GET', 'POST'))
@login_required
def CambioCorreo():
    if request.method == 'POST':
        error = None

        if not title:
            error = 'Title is required.'

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'UPDATE user SET email = ?'
                ' WHERE id = ?',
                (email)
            )
            db.commit()
            return redirect(url_for('blog.index'))

    return render_template('auth/modificacionEmail.html', post=post)    