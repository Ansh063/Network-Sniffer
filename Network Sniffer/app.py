from flask import Flask,render_template,url_for,request,redirect, make_response, jsonify
import random
import json
import pickle
from time import time
from random import random
import numpy as np
from flask import Flask, render_template, make_response
app = Flask(__name__, template_folder='templates')
from flask_packet import getPacketsPersecond



@app.route('/',  methods=["GET", "POST"])
def main():
    return render_template('login.html')



@app.route('/dashboard', methods=["GET", "POST"])
def dashboard1():
    return render_template('iot_index.html')

@app.route('/sniffer', methods=["GET", "POST"])
def sniffer():
    return render_template('index3.html')

@app.route('/devices', methods=["GET", "POST"])
def dashboard2():
    return render_template('devices.html')



@app.route('/predict', methods=["GET", "POST"])
def predict():
    model = pickle.load(open('model.pkl', 'rb'))
    '''
    For rendering results on HTML GUI
    '''
    x_features = [str(x) for x in request.form.values()]
    z_features = [60, int(x_features[8]), 64, 6, int(x_features[0]), 80, int(x_features[5]), int(x_features[6]),
                  int(x_features[4]), 40, int(x_features[9]), int(x_features[7]), 0, 0x00000000, int(x_features[3], 16),
                  int(x_features[2], 16), 0x00000002, int(x_features[1], 16)]

    final_features = [np.array(z_features)]


    prediction = model.predict(final_features)

    output = prediction[0]
    dictionary_unique = {0: 'Aria', 1: 'D-LinkHomeHub', 2: 'D-LinkSiren', 3: 'D-LinkSwitch', 4: 'D-LinkWaterSensor',
                         5: 'EdimaxPlug1101W', 6: 'EdimaxPlug2101W',
                         7: 'TCP_Assistant', 8: 'TCP_Camera', 9: 'TCP_Miscellaneous', 10: 'TCP_Mobile',
                         11: 'TCP_Outlet'}

    return render_template('iot_index.html', prediction_text='IOT DEVICE should be  {}'.format(dictionary_unique[output]))


@app.route('/data', methods=["GET", "POST"])
def data():
    # Data Format
    # [TIME, Temperature, Humidity]

    ICMP, TCP, UDP = getPacketsPersecond()

    data = [time() * 4000, ICMP, TCP, UDP]

    response = make_response(json.dumps(data))

    response.content_type = 'application/json'
    print(response.data)
    return response




if __name__ == "__main__":
    app.run(debug=True)