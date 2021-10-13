#from flask import Blueprint, url_for
#from werkzeug.utils import redirect
from flask import Blueprint, render_template

bp = Blueprint('main', __name__, url_prefix='/')


@bp.route('/hello')
def hello():
    return 'Hello, World!'


@bp.route('/')
def index():
    #return redirect(url_for('cve._list'))
    return render_template('main/main_page.html')
