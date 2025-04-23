# Secure Coding

## Tiny Secondhand Shopping Platform.

You should add some functions and complete the security requirements.

## requirements

if you don't have a miniconda(or anaconda), you can install it on this url. - https://docs.anaconda.com/free/miniconda/index.html

```
git clone https://github.com/ugonfor/secure-coding
conda env create -f enviroments.yaml
```
```
pip install flask
pip install flask-socketio
pip install bleach
pip install werkzeug
```

## credentials
test:p@ssw0rd
test2:12345678
user:p@ssw0rd
admin:12345678
패스워드가 12345678인 것은 패스워드 정책을 설정하기 전에 생성했던 계정이라서 그렇습니다.

## usage

run the server process.

```
python app.py
```

if you want to test on external machine, you can utilize the ngrok to forwarding the url.
```
# optional
sudo snap install ngrok
ngrok http 5000
```