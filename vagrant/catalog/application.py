from flask import Flask, render_template, request, redirect, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from model import Base, User, Category, Stuff

app = Flask(__name__)

engine = create_engine('sqlite:///stuff.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# cRud
@app.route('/')
def showCategoriesAndStuff():
    categories = session.query(Category).order_by(asc(Category.name))
    stuff = session.query(Stuff).order_by(asc(Stuff.name))
    return render_template('stuff.html', categories=categories,
        stuff=stuff)

# Crud
@app.route('/categories/new', methods=['GET', 'POST'])
def createNewCategory():
    if request.method == 'POST':
        newCategory = Category(name=request.form['name'], user_id=0)
        session.add(newCategory)
        flash('New Category %s created successfully' % newCategory.name)
        session.commit()
        return redirect(url_for('showCategoriesAndStuff'))
    else:
        return render_template('newCategory.html')

# Crud
@app.route('/stuff/new', methods=['GET', 'POST'])
def createNewStuff():
    if request.method == 'POST':
        newStuff = Stuff(name=request.form['name'],
            description=request.form['description'],
            category_id=0,
            user_id=0)
        session.add(newStuff)
        flash('New Stuff %s created successfully' % newStuff.name)
        session.commit()
        return redirect(url_for('showCategoriesAndStuff'))
    else:
        return render_template('newStuff.html')

if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
