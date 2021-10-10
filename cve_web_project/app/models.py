from app import db


class CVE_info(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cve_number = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text(), nullable=False)
