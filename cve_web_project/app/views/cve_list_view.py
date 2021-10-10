from flask import Blueprint, render_template, url_for, request
from werkzeug.utils import redirect

from app import db
from app.models import CVE_info

bp = Blueprint('cve', __name__, url_prefix='/cve')


@bp.route('/list/')
def _list():
    cve_list = CVE_info.query.all()
    return render_template('cve/cve_list.html', cve_list=cve_list)


@bp.route('/create', methods=('POST',))
def create():
    cve_number = request.form['cve_number']
    cve = CVE_info(cve_number=cve_number, content='')
    db.session.add(cve)
    db.session.commit()
    return redirect(url_for('cve._list'))
