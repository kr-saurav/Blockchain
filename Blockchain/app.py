from flask import Flask, jsonify, request, render_template
from uuid import uuid4
import requests
from blockchain import *
import _pickle as pickle
import json

app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False

myadd = 'http://0.0.0.0:5000'

myWallet = Wallet()
otherWallet = Wallet()
print('Public key of other user............')
otherkey = otherWallet.publicKey.export_key(format='PEM')
print(otherkey)

B = Blockchain(myWallet)
block = Block(B.blockchain[-1].Hash)
Peers = []


def makekey(key):
    header = '-----BEGIN PUBLIC KEY-----\n'
    footer = '\n-----END PUBLIC KEY-----'
    return header+key+footer

def makemsg(myadd=myadd, type='PING', data=''):
    msg = {
        'sender':myadd,
        'type':type,
        'data':data
    }
    return msg


def getpeers(peer):
    print("/getpeers invoked")
    msg = makemsg(myadd,'GETPEERS', '')
    url = peer+'/querypeer'
    try:
        data = requests.post(url=url, json=msg)
        for peer in data.json()['data']['Peers']:
            if peer not in Peers:
                Peers.append(peer)
        print(Peers)
        return True
    except :
        print('Error occured in getting peers')
        return False
    

def addme():
    print(".........addme invoked")
    #data = request.get_json()
    msg = makemsg(myadd, 'ADDME', '')
    count = 0
    for peer in Peers:
        if peer==myadd:
            continue
        url = peer+'/querypeer'
        #url = peer1+'/querypeer'
        try:
            data = requests.post(url=url, json=msg)
            count+=1
        except:
            print('Error in adding to '+peer)
            try:
                Peers.remove(peer)
            except:
                print('Peer not in list')
    return count

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/blockchain', methods = ['GET'])
def show():
    return render_template('blockchain.html', blockchain=B.blockchain, length=len(B.blockchain))

@app.route('/blockchain/<index>', methods=['GET'])
def showtransaction(index):
    index = int(index)
    if index >= len(B.blockchain):
        response = 'Block does not exist yet'
        return render_template('show.html', response=response)
    return render_template('transactions.html', transactions=B.blockchain[index].transactions, index=index)

@app.route('/connect', methods = ['GET', 'Post'])
def connect():
    if request.method == 'GET':
        return render_template('connect.html')
    elif request.method == 'POST':
        peer = request.form['peer']
        try:
            if getpeers(peer):
                #getpeer() to get list of addresses of all peers in network
                #addme() to connect to all peers
                if peer not in Peers:
                    Peers.append(peer)
                count = addme()
                #print(Peers)
                return render_template('network.html', Peers = enumerate(Peers), length=len(Peers))
            else:   
                #abort(404)  # 404 Not Found
                #abort(Response('Hello World'))
                response = 'Invalid address'
                return render_template('show.html', response=response, good=False)
        except Exception as e:
            response = 'Error Occured '+str(e)
            return render_template('show.html', response=response,good=False)

@app.route('/peers', methods=['GET'])
def mypeers():
    global Peers
    return render_template('network.html', Peers = enumerate(Peers), length=len(Peers))

@app.route('/sync', methods = ['GET'])
def sync():
    response = 'Not available.......(this link is part of P2P network which is still in Development!)'
    return render_template('show.html', response=response,good=False)
    print('/sync invoked')    
    msg = makemsg(myadd, 'CHAIN_LENGTH','')
    for peer in Peers:
        url = peer
        #url = peer1+'/querypeer'
        try:
            print("....herre")
            data = requests.post(url=url, json=msg)
            print(data.json()['data'])
            if data.status_code == 404:
                print('Error in connecting to '+peer)
            else:
                global chain
                if len(chain) < data.json()['data']['length']:
                    message = makemsg(myadd, 'GET_CHAIN', '')
                    try:
                        r = requests.post(url=url, json=message)
                        y = pickle.loads(r.content)
                        print(y)
                        #o = pickle.loads(r.json())
                        #print(o)
                        #print()
                        #peerchain = r.json()['data']['chain']
                        #if verifychain(peerchain):
                        #    chain = peerchain
                        #chain = peerchain
                        #print(peerchain)
                        #print('chain synced')
                    except Exception as e:
                        print('Error in sync with '+str(peer)+'::Error-'+str(e))
                        pass
        except Exception as e:
            response = {
                'Status':'Error Occured '+str(e)
            }
            return jsonify(response)
    print(chain)
    response = {
        'Status':'Chain synced',
        'Chain':chain
    }    
    return jsonify(response)

@app.route('/addtransaction', methods = ['GET'])
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
        'Status':'Transactions sent',
        'transactions':new_transaction
    }    
    return jsonify(response)

@app.route('/wallet', methods = ['GET','POST'])
def wallet():
    if request.method == 'GET':
        return render_template('wallet.html', balance=myWallet.getBalance())
    elif request.method == 'POST':
        result = request.form
        reciepient = result['receiver']
        amount = int(result['amount'])
        public_key = ECC.import_key(makekey(reciepient))
        #print(public_key)
        
        global block
        success = block.addTransaction(myWallet.sendFunds(public_key, amount))
        print('Balance of other user :: '+str(otherWallet.getBalance()))
        #print(otherWallet.getBalance())
        return render_template('receipt.html', result=result, success=success)


@app.route('/mine', methods=['GET'])
def mine():
    global block
    if len(block.transactions)>0: 
        time_taken = B.addBlock(block)
        block = Block(B.blockchain[-1].Hash)
        return render_template('mine.html', time=time_taken, flag=True)
    else:
        return render_template('mine.html', flag=False)

@app.route('/mykeys', methods=['GET'])
def getkey():
    #geneating private key
    key = myWallet.privateKey
    f = open('myprivatekey.pem','wt')
    f.write(key.export_key(format='PEM'))
    f.close()
    #generating public key
    f = open('mypublickey.txt','wt')
    #saving in a form that this software accepts
    public_key = myWallet.publicKey.export_key(format='PEM')[26:-24]
    f.write(public_key)
    f.close
    response = 'Keys generated and stored in myprivatekey.pem and mypublickey.txt'
    return render_template('show.html', response=response,good=True)

@app.route('/isValid', methods=['GET'])
def IsValid():
    response = ''
    if len(B.blockchain)>1:
        flag = B.isChainValid()
        if not flag:
            response = 'Chain is not valid....(look in to terminal further inquiry)'
            return render_template('show.html',response=response,good=False)
        else:
            response = 'Chain is Valid!'
    else:
        response = 'Chain is Valid!'
    return render_template('show.html',response=response,good=True)

@app.route('/about', methods=['GET'])
def about():
    return render_template('about.html')

@app.route('/querypeer', methods = ['POST'])
def peerquery():
    print("/querypeer invoked")
    data = request.get_json()
    #if else statement to invoke
    #print(data)
    print(data)
    if data['type']=='ADDME':
        print("Adding peer : "+data['sender'])
        global Peers
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
            'chain':chain
        }
        response = makemsg(myadd, 'RESPONSE', msg)
        return jsonify(response)
    elif data['type']=='NEW_TRANSACTION':
        print('Adding new transaction')
        new_transaction = data['data']
        if new_transaction not in transactions:
            transactions.append(new_transaction)
    else: 
        print('Invalid type...')

        response = makemsg(myadd, 'RESPONSE', 'Added successfully')
        return jsonify(response)        
        #perform mining and other checks
    return jsonify(response)

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=5000,debug=True)
    
    '''app.debug = True
    server = WSGIServer(("", 5000), app)
    server.serve_forever()
   ''' 
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