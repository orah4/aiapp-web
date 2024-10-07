from flask import Flask, request, render_template, redirect, url_for
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import networkx as nx
import matplotlib.pyplot as plt
import base64

app = Flask(__name__)

# Generate a random 16-byte AES key
key = os.urandom(16)

def encrypt_data(data):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ciphertext  # Prepend IV for decryption

def decrypt_data(data):
    iv = data[:16]  # Extract the IV
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

def create_network_graph():
    G = nx.Graph()
    nodes = ['Normal', 'DOS', 'U2R', 'R2L', 'Probe']
    edges = [('Normal', 'Normal'), ('Normal', 'DOS'), ('Normal', 'U2R'), ('Normal', 'R2L'), ('Normal', 'Probe')]
    
    G.add_nodes_from(nodes)
    G.add_edges_from(edges)

    # Draw the graph
    plt.figure(figsize=(8, 6))
    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True, node_color='skyblue', node_size=2000, font_size=15, font_weight='bold')
    plt.title("Network Data Transmission Snitch", size=15)
    plt.savefig('static/network_graph.png')
    plt.close()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            file_path = os.path.join('uploads', file.filename)
            file.save(file_path)

            # Encrypt the file content
            with open(file_path, 'rb') as f:
                file_data = f.read()
            encrypted_data = encrypt_data(file_data)

            # Convert encrypted data to base64 for display
            encrypted_data_b64 = base64.b64encode(encrypted_data).decode('utf-8')

            # Save the encrypted data
            encrypted_file_path = file_path + '.enc'
            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_data)

            return redirect(url_for('result', filename=file.filename, encrypted_data=encrypted_data_b64))
    return render_template('index.html')

@app.route('/result/<filename>')
def result(filename):
    # Create the network graph for visualization
    create_network_graph()
    encrypted_data = request.args.get('encrypted_data')
    return render_template('result.html', filename=filename, encrypted_data=encrypted_data)

@app.route('/decrypt/<filename>')
def decrypt(filename):
    encrypted_file_path = os.path.join('uploads', filename + '.enc')
    decrypted_file_path = os.path.join('uploads', filename)
    with open(encrypted_file_path, 'rb') as f:
        encrypted_data = f.read()

    decrypted_data = decrypt_data(encrypted_data)
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)
    
    return f'Decrypted {filename} successfully!'

@app.route('/graph')
def graph():
    return render_template('graph.html')

if __name__ == '__main__':
    app.run(debug=True)
