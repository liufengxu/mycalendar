#!/usr/bin/env python
# -*- coding: utf-8 -*-
################################################################################
#
# Copyright (c) 2015 .com, Inc. All Rights Reserved
#
################################################################################
"""
description:
author: liufengxu
date: 2015-07-26 20:57:51
last modified: 2015-08-11 00:54:40
version:
"""

import logging
import os
import time
from flask import Flask
from flask import jsonify
from flask import request
from flask import g
from flask.ext.sqlalchemy import SQLAlchemy
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from werkzeug import secure_filename
import uuid
import urllib
import urllib2
import json
import base64
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

import tag
import voice_plan


LOCAL_IP = '172.22.237.255'
UPLOAD_FOLDER = '/Users/baidu/code/calendar/uploads'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'Biubiz zhanyezhushou'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:xgcg2015@127.0.0.1/zhanye'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# extensions
db = SQLAlchemy(app)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


def image2base64(image_file):
    with open(image_file) as fp:
        base = base64.b64encode(fp.read())
    return base


@app.route('/upload_pic', methods=['POST'])
def pack_json(data_dict, message='error'):
    logging.debug('%s', data_dict)
    if not data_dict:
        return jsonify({'status': 1, 'message': message, 'data': {}})
    return jsonify({'status': 0, 'message': message, 'data': data_dict})


def upload_file():
    if request.files:
        logging.debug('%s', request.files)
    file = request.files['file']
    if file and allowed_file(file.filename):
        logging.debug('ensure security')
        filename = secure_filename(file.filename)
        filename = str(uuid.uuid1()) + '.' + filename.rsplit('.', 1)[1]
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        ret_dict = {}
        ret_dict['pic_name'] = filename
        return pack_json(ret_dict, 'success')
    return pack_json({})


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(128))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=86400):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None    # valid token, but expired
        except BadSignature:
            return None    # invalid token
        user = User.query.get(data['id'])
        return user


def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/user/register', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        return pack_json({})    # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        return pack_json({})    # missing arguments
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return pack_json({'username': user.username}, 'success'), 201


@app.route('/user/get', methods=['POST'])
def get_user():
    username = request.json.get('username')
    token = request.json.get('token')
    if token and verify_password(token, ''):
        user = User.query.filter_by(username=username).first()
        if user:
            return pack_json({'user_id': user.id, 'username': user.username},
                             'success')
        logging.debug('no such usera')
    logging.debug('token not verified')
    return pack_json({})


@app.route('/token', methods=['POST'])
def get_auth_token():
    username = request.json.get('username')
    password = request.json.get('password')
    if username and password:
        if verify_password(username, password):
            token = g.user.generate_auth_token(86400)
            ret_dict = {'token': token.decode('ascii'), 'duration': 86400}
            return pack_json(ret_dict, 'success')
    return pack_json({})


class Plan(db.Model):
    __tablename__ = 'plans'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    title = db.Column(db.String(64))
    content = db.Column(db.String(256))
    address = db.Column(db.String(128))
    start = db.Column(db.Integer)
    end = db.Column(db.Integer)
    remind = db.Column(db.Integer)
    is_done = db.Column(db.Boolean)

    def set_title(self, title):
        if title:
            self.title = title

    def set_content(self, content):
        if content:
            self.content = content

    def set_address(self, address):
        if address:
            self.address = address

    def set_start(self, start):
        if start:
            self.start = start

    def set_end(self, end):
        if end:
            self.end = end

    def set_remind(self, remind):
        if remind:
            self.remind = remind

    def set_is_done(self, is_done):
        if is_done:
            if is_done.lower() == "true":
                self.is_done = True
        self.is_done = False


@app.route('/plan/get', methods=['POST'])
def get_plan():
    logging.debug('start to get a plan by id')
    token = request.json.get('token')
    if token and verify_password(token, ''):
        plan_id = request.json.get('plan_id')
        plan = Plan.query.get(plan_id)
        logging.debug('get plan')
        if not plan:
            return pack_json({})
        ret_dict = {'title': plan.title, 'content': plan.content,
                    'address': plan.address, 'start': plan.start,
                    'end': plan.end, 'remind': plan.remind,
                    'is_done': plan.is_done, 'id': plan.id,
                    'user_id': plan.user_id}
        return pack_json(ret_dict, 'success'), 201
    logging.debug('token not verified')
    return pack_json({})


@app.route('/plan/getall', methods=['POST'])
def get_all_plan():
    logging.debug('start to get a plan by user id')
    token = request.json.get('token')
    if token and verify_password(token, ''):
        user_id = request.json.get('user_id')
        plans = Plan.query.filter_by(user_id=user_id).all()
        logging.debug('%s', plans)
        if not plans:
            return pack_json({})
        ret_dict = {}
        ret_list = []
        for plan in plans:
            tmp_ret_dict = {'title': plan.title, 'content': plan.content,
                            'address': plan.address, 'start': plan.start,
                            'end': plan.end, 'remind': plan.remind,
                            'is_done': plan.is_done, 'id': plan.id,
                            'user_id': plan.user_id}
            ret_list.append(tmp_ret_dict)
        ret_dict['plan_list'] = ret_list
        ret_dict['more'] = 0
        return pack_json(ret_dict, 'success'), 201
    logging.debug('token not verified')
    return pack_json({})


@app.route('/plan/create', methods=['POST'])
def new_plan():
    logging.debug('start to new a plan')
    token = request.json.get('token')
    if token and verify_password(token, ''):
        user_id = request.json.get('user_id')
        title = request.json.get('title')
        content = request.json.get('content')
        address = request.json.get('address')
        start = request.json.get('start')
        end = request.json.get('end')
        remind = request.json.get('remind')
        is_done_str = request.json.get('is_done')
        if not user_id:
            logging.error('No user id')
            return pack_json({})
        if not title:
            title = ''
        if not content:
            content = ''
        if not address:
            address = ''
        if not start:
            start = int(time.time())
        if not end:
            end = int(time.time())
        if not remind:
            remind = int(time.time())
        if is_done_str.lower() == "true":
            is_done = True
        else:
            is_done = False
        plan = Plan(title=title, content=content, address=address, end=end,
                    start=start, remind=remind, is_done=is_done,
                    user_id=user_id)
        db.session.add(plan)
        db.session.commit()
        new_trace(plan.user_id, ' 创建了计划 ', plan.title)
        ret_dict = {'title': plan.title, 'content': plan.content,
                    'address': plan.address, 'start': plan.start,
                    'end': plan.end, 'remind': plan.remind,
                    'is_done': plan.is_done, 'id': plan.id,
                    'user_id': plan.user_id}
        return pack_json(ret_dict, 'success'), 201
    logging.debug('token not verified')
    return pack_json({})


@app.route('/plan/createbyvoice', methods=['POST'])
def new_plan_by_voice():
    logging.debug('start to new a plan')
    token = request.json.get('token')
    if token and verify_password(token, ''):
        user_id = request.json.get('user_id')
        content = request.json.get('voice')
        is_done = False
        start, end, address, title, remind = voice_plan.voice_parser(content)
        if not user_id:
            logging.error('No user id')
            return pack_json({})
        if not title:
            title = ''
        if not content:
            content = ''
        if not address:
            address = ''
        if not start:
            start = int(time.time())
        if not end:
            end = int(time.time())
        if not remind:
            remind = int(time.time()-3600)
        else:
            is_done = False
        plan = Plan(title=title, content=content, address=address, end=end,
                    start=start, remind=remind, is_done=is_done,
                    user_id=user_id)
        db.session.add(plan)
        db.session.commit()
        new_trace(plan.user_id, ' 创建了计划 ', plan.title)
        ret_dict = {'title': plan.title, 'content': plan.content,
                    'address': plan.address, 'start': plan.start,
                    'end': plan.end, 'remind': plan.remind,
                    'is_done': plan.is_done, 'id': plan.id,
                    'user_id': plan.user_id}
        return pack_json(ret_dict, 'success'), 201
    logging.debug('token not verified')
    return pack_json({})


@app.route('/plan/update', methods=['POST'])
def update_plan():
    token = request.json.get('token')
    if token and verify_password(token, ''):
        plan_id = request.json.get('plan_id')
        plan = Plan.query.get(plan_id)
        if not plan:
            return pack_json({})
        title = request.json.get('title')
        content = request.json.get('content')
        address = request.json.get('address')
        start = request.json.get('start')
        end = request.json.get('end')
        remind = request.json.get('remind')
        is_done = request.json.get('is_done')
        plan.set_title(title)
        plan.set_content(content)
        plan.set_address(address)
        plan.set_start(start)
        plan.set_end(end)
        plan.set_remind(remind)
        plan.set_is_done(is_done)
        db.session.merge(plan)
        db.session.commit()
        new_trace(plan.user_id, ' 更新了计划 ', plan.title)
        ret_dict = {'title': plan.title, 'content': plan.content,
                    'address': plan.address, 'start': plan.start,
                    'end': plan.end, 'remind': plan.remind,
                    'is_done': plan.is_done, 'id': plan.id,
                    'user_id': plan.user_id}
        return pack_json(ret_dict, 'success'), 201
    logging.debug('token not verified')
    return pack_json({})


@app.route('/plan/delete', methods=['POST'])
def delete_plan():
    token = request.json.get('token')
    if token and verify_password(token, ''):
        plan_id = request.json.get('plan_id')
        plan = Plan.query.get(plan_id)
        db.session.delete(plan)
        db.session.commit()
        new_trace(plan.user_id, ' 删除了计划 ', plan.title)
        return pack_json({'deleted_plan_id': plan_id}, 'success')
    logging.debug('token not verified')
    return pack_json({})


class Contact(db.Model):
    __tablename__ = 'contacts'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    name = db.Column(db.String(64))
    company = db.Column(db.String(256))
    position = db.Column(db.String(128))
    tel = db.Column(db.String(32))
    mobile = db.Column(db.String(32))
    email = db.Column(db.String(32))
    address = db.Column(db.String(128))

    def set_name(self, name):
        if name:
            self.name = name

    def set_company(self, company):
        if company:
            self.company = company

    def set_position(self, position):
        if position:
            self.position = position

    def set_tel(self, tel):
        if tel:
            self.tel = tel

    def set_mobile(self, mobile):
        if mobile:
            self.mobile = mobile

    def set_email(self, email):
        if email:
            self.email = email

    def set_address(self, address):
        if address:
            self.address = address


@app.route('/contact/get', methods=['POST'])
def get_contact(contact_id):
    logging.debug('start to get a contact by id')
    token = request.json.get('token')
    if token and verify_password(token, ''):
        contact_id = request.json.get('contact_id')
        contact = Contact.query.get(contact_id)
        logging.debug('get contact')
        if not contact:
            return pack_json({})
        ret_dict = {'name': contact.name, 'company': contact.company,
                    'address': contact.address, 'position': contact.position,
                    'tel': contact.tel, 'mobile': contact.mobile,
                    'email': contact.email, 'id': contact.id,
                    'user_id': contact.user_id}
        return pack_json(ret_dict, 'success'), 201
    logging.debug('token not verified')
    return pack_json({})


@app.route('/contact/getall', methods=['POST'])
def get_all_contact():
    logging.debug('start to get a contact by user id')
    token = request.json.get('token')
    if token and verify_password(token, ''):
        user_id = request.json.get('user_id')
        contacts = Contact.query.filter_by(user_id=user_id).all()
        logging.debug('%s', contacts)
        if not contacts:
            return pack_json({})
        ret_dict = {}
        ret_list = []
        for contact in contacts:
            tmp_ret_dict = {'name': contact.name, 'company': contact.company,
                            'address': contact.address,
                            'position': contact.position,
                            'tel': contact.tel, 'mobile': contact.mobile,
                            'email': contact.email, 'id': contact.id,
                            'user_id': contact.user_id}
            ret_list.append(tmp_ret_dict)
        ret_dict['contact_list'] = ret_list
        ret_dict['more'] = 0
        return pack_json(ret_dict, 'success'), 201
    logging.debug('token not verified')
    return pack_json({})


@app.route('/contact/create', methods=['POST'])
def new_contact():
    logging.debug('start to new a contact')
    token = request.json.get('token')
    if token and verify_password(token, ''):
        user_id = request.json.get('user_id')
        name = request.json.get('name')
        company = request.json.get('company')
        address = request.json.get('address')
        tel = request.json.get('tel')
        position = request.json.get('position')
        mobile = request.json.get('mobile')
        email = request.json.get('email')
        if not user_id:
            logging.error('No user id')
            return pack_json({})
        if not name:
            name = ''
        if not company:
            company = ''
        if not address:
            address = ''
        if not tel:
            tel = ''
        if not position:
            position = ''
        if not mobile:
            mobile = ''
        if not email:
            email = ''
        contact = Contact(name=name, company=company, address=address, tel=tel,
                          position=position, mobile=mobile, email=email,
                          user_id=user_id)
        db.session.add(contact)
        db.session.commit()
        new_trace(contact.user_id, ' 创建了联系人 ', contact.name)
        ret_dict = {'name': contact.name, 'company': contact.company,
                    'address': contact.address, 'position': contact.position,
                    'tel': contact.tel, 'mobile': contact.mobile,
                    'email': contact.email, 'id': contact.id,
                    'user_id': contact.user_id}
        return pack_json(ret_dict, 'success'), 201
    logging.debug('token not verified')
    return pack_json({})


@app.route('/contact/createbyphoto', methods=['POST'])
def new_contact_by_photo():
    logging.debug('start to create plan by photo')
    token = request.json.get('token')
    logging.debug('start to create plan by photo')
    if token and verify_password(token, ''):
        user_id = request.json.get('user_id')
        image_file = request.json.get('image_file')
        image_file = UPLOAD_FOLDER + '/' + image_file
        baidu_ocr_url = 'http://apis.baidu.com/apistore/idlocr/ocr'
        data = {}
        data['fromdevice'] = "pc"
        data['clientip'] = LOCAL_IP
        data['detecttype'] = "LocateRecognize"
        data['languagetype'] = "CHN_ENG"
        data['imagetype'] = "1"
        data['image'] = image2base64(image_file)
        decoded_data = urllib.urlencode(data)
        logging.debug('%s', decoded_data)
        req = urllib2.Request(baidu_ocr_url, data=decoded_data)
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("apikey", "39455bc05359c2d5615a8489b21229be")
        resp = urllib2.urlopen(req)
        content = resp.read()
        if content:
            # print json.JSONDecoder().decode(content)['errMsg']
            name = ''
            company = ''
            address = ''
            tel = ''
            position = ''
            mobile = ''
            email = ''
            for area in json.JSONDecoder().decode(content)['retData']:
                to_rec = area['word']
                plan_tag, content = tag.business_card_rule(to_rec)
                if plan_tag == 'name':
                    name = content
                if plan_tag == 'mobile':
                    mobile = content
                if plan_tag == 'email':
                    email = content
                if plan_tag == 'position':
                    position = content
                if plan_tag == 'company':
                    company = content
                if plan_tag == 'tel':
                    tel = content
                if plan_tag == 'address':
                    address = content
                contact = Contact(name=name, company=company, address=address,
                                  tel=tel, position=position, mobile=mobile,
                                  email=email, user_id=user_id)
                db.session.add(contact)
                db.session.commit()
                new_trace(contact.user_id, ' 创建了联系人 ', contact.name)
                ret_dict = {'name': contact.name, 'company': contact.company,
                            'address': contact.address,
                            'position': contact.position,
                            'tel': contact.tel, 'mobile': contact.mobile,
                            'email': contact.email, 'id': contact.id,
                            'user_id': contact.user_id}
                return pack_json(ret_dict, 'success'), 201
        logging.debug('no content')
        return pack_json({})
    logging.debug('token not verified')
    return pack_json({})


@app.route('/contact/update', methods=['POST'])
def update_contact():
    token = request.json.get('token')
    if token and verify_password(token, ''):
        contact_id = request.json.get('contact_id')
        contact = Contact.query.get(contact_id)
        if not contact:
            return pack_json({})
        name = request.json.get('name')
        company = request.json.get('company')
        position = request.json.get('position')
        tel = request.json.get('tel')
        address = request.json.get('address')
        mobile = request.json.get('mobile')
        email = request.json.get('email')
        contact.set_name(name)
        contact.set_company(company)
        contact.set_address(address)
        contact.set_position(position)
        contact.set_tel(tel)
        contact.set_mobile(mobile)
        contact.set_email(email)
        db.session.merge(contact)
        db.session.commit()
        new_trace(contact.user_id, ' 更新了联系人 ', contact.name)
        ret_dict = {'name': contact.name, 'company': contact.company,
                    'address': contact.address, 'position': contact.position,
                    'tel': contact.tel, 'mobile': contact.mobile,
                    'email': contact.email, 'id': contact.id,
                    'user_id': contact.user_id}
        return pack_json(ret_dict, 'success'), 201
    logging.debug('token not verified')
    return pack_json({})


@app.route('/contact/delete', methods=['POST'])
def delete_contact():
    token = request.json.get('token')
    if token and verify_password(token, ''):
        contact_id = request.json.get('contact_id')
        contact = Contact.query.get(contact_id)
        db.session.delete(contact)
        db.session.commit()
        new_trace(contact.user_id, ' 删除了联系人 ', contact.name)
        return pack_json({'deleted_contact_id': contact_id}, 'success')
    logging.debug('token not verified')
    return pack_json({})


class Note(db.Model):
    __tablename__ = 'notes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    title = db.Column(db.String(64))
    content = db.Column(db.String(256))

    def set_title(self, title):
        if title:
            self.title = title

    def set_content(self, content):
        if content:
            self.content = content


@app.route('/note/get', methods=['POST'])
def get_note():
    logging.debug('start to get a note by id')
    token = request.json.get('token')
    if token and verify_password(token, ''):
        note_id = request.json.get('note_id')
        note = Note.query.get(note_id)
        logging.debug('get note')
        if not note:
            return pack_json({})
        ret_dict = {'title': note.title, 'content': note.content,
                    'id': note.id, 'user_id': note.user_id}
        return pack_json(ret_dict, 'success'), 201
    logging.debug('token not verified')
    return pack_json({})


@app.route('/note/getall', methods=['POST'])
def get_all_note():
    logging.debug('start to get a note by user id')
    token = request.json.get('token')
    if token and verify_password(token, ''):
        user_id = request.json.get('user_id')
        notes = Note.query.filter_by(user_id=user_id).all()
        logging.debug('%s', notes)
        if not notes:
            return pack_json({})
        ret_dict = {}
        ret_list = []
        for note in notes:
            tmp_ret_dict = {'title': note.title, 'content': note.content,
                            'id': note.id, 'user_id': note.user_id}
            ret_list.append(tmp_ret_dict)
        ret_dict['note_list'] = ret_list
        ret_dict['more'] = 0
        return pack_json(ret_dict, 'success'), 201
    logging.debug('token not verified')
    return pack_json({})


@app.route('/note/create', methods=['POST'])
def new_note():
    logging.debug('start to new a note')
    token = request.json.get('token')
    if token and verify_password(token, ''):
        user_id = request.json.get('user_id')
        title = request.json.get('title')
        content = request.json.get('content')
        if not user_id:
            logging.error('No user id')
            return pack_json({})
        if not title:
            title = ''
        if not content:
            content = ''
        note = Note(title=title, content=content, user_id=user_id)
        db.session.add(note)
        db.session.commit()
        new_trace(note.user_id, ' 创建了笔记 ', note.title)
        ret_dict = {'title': note.title, 'content': note.content,
                    'id': note.id, 'user_id': note.user_id}
        return pack_json(ret_dict, 'success'), 201
    logging.debug('token not verified')
    return pack_json({})


@app.route('/note/update', methods=['POST'])
def update_note():
    token = request.json.get('token')
    if token and verify_password(token, ''):
        note_id = request.json.get('note_id')
        note = Note.query.get(note_id)
        if not note:
            return pack_json({})
        title = request.json.get('title')
        content = request.json.get('content')
        note.set_title(title)
        note.set_content(content)
        db.session.merge(note)
        db.session.commit()
        new_trace(note.user_id, ' 更新了笔记 ', note.title)
        ret_dict = {'title': note.title, 'content': note.content,
                    'id': note.id, 'user_id': note.user_id}
        return pack_json(ret_dict, 'success'), 201
    logging.debug('token not verified')
    return pack_json({})


@app.route('/note/delete', methods=['POST'])
def delete_note():
    token = request.json.get('token')
    if token and verify_password(token, ''):
        note_id = request.json.get('note_id')
        note = Note.query.get(note_id)
        db.session.delete(note)
        db.session.commit()
        new_trace(note.user_id, ' 删除了笔记 ', note.title)
        return pack_json({'deleted_note_id': note_id}, 'success')
    logging.debug('token not verified')
    return pack_json({})


class Trace(db.Model):
    __tablename__ = 'traces'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    trace_time = db.Column(db.Integer)
    content = db.Column(db.String(64))


def new_trace(user_id, prefix, title):
    content = prefix + title
    trace_time = int(time.time())
    trace = Trace(user_id=user_id, trace_time=trace_time, content=content)
    db.session.add(trace)
    db.session.commit()


@app.route('/trace/delete', methods=['POST'])
def delete_trace():
    token = request.json.get('token')
    if token and verify_password(token, ''):
        trace_id = request.json.get('trace_id')
        trace = Note.query.get(trace_id)
        db.session.delete(trace)
        db.session.commit()
        return pack_json({'deleted_trace_id': trace_id}, 'success')
    logging.debug('token not verified')
    return pack_json({})


@app.route('/trace/getall', methods=['POST'])
def get_all_trace():
    token = request.json.get('token')
    if token and verify_password(token, ''):
        user_id = request.json.get('user_id')
        traces = Trace.query.filter_by(user_id=user_id).all()
        logging.debug('%s', traces)
        if not traces:
            return pack_json({})
        ret_dict = {}
        ret_list = []
        for trace in traces:
            tmp_ret_dict = {'trace_time': trace.trace_time,
                            'content': trace.content,
                            'id': trace.id, 'user_id': trace.user_id}
            ret_list.append(tmp_ret_dict)
        ret_dict['trace_list'] = ret_list
        ret_dict['more'] = 0
        return pack_json(ret_dict, 'success'), 201
    logging.debug('token not verified')
    return pack_json({})

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: "
                        "%(asctime)s: %(filename)s: %(lineno)d * "
                        "%(thread)d %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S")
    """  # used for sqlite
    if not os.path.exists('db.sqlite'):
        db.create_all()
        """
    db.create_all()
    app.run(debug=True)
