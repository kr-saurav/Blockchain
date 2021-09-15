from flask import Flask, jsonify, request, render_template
from uuid import uuid4
import requests
from blockchain import *
import json
import pickle

#B = Blockchain()
app = Flask(__name__)
app.config.from_object(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False

node_id = str(uuid4()).replace('-','')
chain = [{'index':1,'data':'1'}, {'index':4, 'data':'4'}, {'index':5, 'data':'5'},{'index':2, 'data':'2'}, {'index':3, 'data':'3'}, {'index':4, 'data':'4'}, {'index':5, 'data':'5'}]
transactions = []
myadd = 'http://0.0.0.0:5001'
Peers = []

class me():
    def __init__(self):
        self.y = 100
class test():
    def __init__(self,x):
        self.x = x
        self.z = me()

t = test(90)

def makemsg(myadd=myadd, type='PING', data=''):
    msg = {
        'sender':myadd,
        'type':type,
        'data':data
    }
    return msg
    
@app.route('/')
def home():
    response = {'Response':'this is homepage'}
    return jsonify(response)

@app.route('/getpeers', methods = ['GET'])
def getpeers():
    print("/getpeers invoked")
    msg = makemsg(myadd,'GETPEERS', '')
    url = peer1+'/querypeer'
    data = requests.post(url=url, json=msg)

    if data.status_code == 404:
        print('Error in Post request')
        response = {'Status':'Error Occured'}
        return jsonify(response)
    else:
        for peer in data.json()['data']['Peers']:
            if peer not in Peers:
                Peers.append(peer)

        print(Peers)
        response = {'Status':'Peer data received'}
        return jsonify(response)


@app.route('/addme', methods = ['GET'])
def querypeer():
    print("/addme invoked")
    #data = request.get_json()
    msg = makemsg(myadd, 'ADDME', '')
    count = 0
    for peer in Peers:
        #url = peer
        url = peer1+'/querypeer'
        data = requests.post(url=url, json=msg)

        if data.status_code == 404:
            print('Error in adding to '+peer)
        else:
            count+=1
    response = {
        'Status':'Total added peers'+str(count)
    }
    return jsonify(response)


def verifychain(peerchain):
    #code
    return True

@app.route('/sync', methods = ['GET'])
def sync():
    print('/sync invoked')    
    msg = makemsg(myadd, 'CHAIN_LENGTH','')
    for peer in Peers:
        #url = peer
        url = peer1+'/querypeer'
        data = requests.post(url=url, json=msg)

        if data.status_code == 404:
            print('Error in connecting to '+peer)
        else:
            #if len(chain)<data.json()['data']['length']:
            message = makemsg(myadd, 'GET_CHAIN', '')
            r = requests.post(url=url, json=message)
            peerchain = r.json()['data']['chain']
            #if verifychain(peerchain):
            #    chain = peerchain
            print(peerchain)
                #chain = peerchain
    #print(chain)
    response = {
        'Status':'Chain synced'
    }    
    return jsonify(response)

@app.route('/addtrasaction', methods = ['GET'])
def addtrasaction():
    print('/addtransaction invoked')
    new_transaction = {'Key1':'Value1', 'Key2':'Value2'}
    msg = makemsg(myadd, 'NEW_TRANSACTION', new_transaction)
    for peer in Peers:
        #url = peer
        url = peer1+'/querypeer'
        data = requests.post(url=url, json=msg)
        if data.status_code == 404:
            print('Error in connecting to '+peer)
    response = {
        'Status':'Transactions sent'
    }    
    return jsonify(response)



@app.route('/querypeer', methods = ['POST'])
def peerquery():
    print("/querypeer invoked")
    data = request.get_json()
    #if else statement to invoke
    #print(data)
    print(data)
    if data['type']=='ADDME':
        print("Adding peer : "+data['sender'])
        if data['sender'] not in Peers:
            Peers.append(data['sender'])
        response = {
            'Status':'Added Successfully'
        }
        return jsonify(response)

    elif data['type']=='GETPEERS':
        print('Sending peers to : '+data['sender'])
        msg = {
            'length':len(Peers),
            'Peers':Peers
        }
        response = makemsg(myadd, 'RESPONSE', msg)
        return jsonify(response)
    elif data['type']=='CHAIN_LENGTH':
        print('Sending chain length to : '+data['sender'])
        msg = {
            'length':len(chain)
        }
        response = makemsg(myadd, 'RESPONSE', msg)
        return jsonify(response)
    elif data['type']=='GET_CHAIN':
        print('Sending chain to : '+data['sender'])
        msg = {
            'length':len(chain),
            'chain':B.blockchain
        }
        try:
            #r = bytes((B.blockchain))
            #print(type(r))
            return jsonify("L")
            #return (r)
        except Exception as e:
            print(e)
            return jsonify('l')
        #response = vars(t)#makemsg(myadd, 'RESPONSE', msg)
        
    elif data['type']=='NEW_TRANSACTION':
        print('Adding new transaction')
        new_transaction = data['data']
        if new_transaction not in transactions:
            transactions.append(new_transaction)

        response = makemsg(myadd, 'RESPONSE', 'Added successfully')
        return jsonify(response)        
        #perform mining and other checks
    return jsonify(response)
    



if __name__ == '__main__':
    app.run(host='0.0.0.0',port=5001)


'''
request = {
    'sender':
    'type':
    'data':
}

response = {
    'sender':
    'type':
    'data':
}
'''