script_a = '''#!/bin/bash -ex
touch /home/ubuntu/startA.txt

exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

apt-get update
apt install docker.io build-essential binutils colorized-logs -y

mkdir -p /home/ubuntu/vuls
cd /home/ubuntu/
wget https://downloads.cisofy.com/lynis/lynis-3.0.3.tar.gz

apt-get install chkrootkit -y

mkdir -p chkrootkit && cd chkrootkit



cd /home/ubuntu/vuls
sudo docker pull vuls/go-cve-dictionary
sudo docker pull vuls/goval-dictionary
sudo docker pull vuls/gost
sudo docker pull vuls/go-exploitdb
sudo docker pull vuls/gost
sudo docker pull vuls/vuls

touch /home/ubuntu/A1.txt
cd /home/ubuntu/vuls


sudo docker run --rm -i \
    -v $PWD:/vuls \
    -v $PWD/go-cve-dictionary-log:/var/log/vuls \
    vuls/go-cve-dictionary fetch nvd

touch /home/ubuntu/A2.txt

sudo docker run --rm -i \
    -v $PWD:/vuls \
    -v $PWD/goval-dictionary-log:/var/log/vuls \
    vuls/goval-dictionary fetch redhat 5 6 7 8



sudo docker run --rm -i \
    -v $PWD:/vuls \
    -v $PWD/goval-dictionary-log:/var/log/vuls \
    vuls/goval-dictionary fetch debian 7 8 9 10
    
sudo docker run --rm -i \
    -v $PWD:/vuls \
    -v $PWD/goval-dictionary-log:/var/log/vuls \
    vuls/goval-dictionary fetch alpine 3.3 3.4 3.5 3.6 3.7 3.8 3.9 3.10 3.11

sudo docker run --rm -i \
    -v $PWD:/vuls \
    -v $PWD/goval-dictionary-log:/var/log/vuls \
    vuls/goval-dictionary fetch ubuntu 14 16 18 19 20



sudo docker run --rm -i \
    -v $PWD:/vuls \
    -v $PWD/goval-dictionary-log:/var/log/vuls \
    vuls/goval-dictionary fetch oracle 

sudo docker run --rm -i \
    -v $PWD:/vuls \
    -v $PWD/goval-dictionary-log:/var/log/vuls \
    vuls/goval-dictionary fetch amazon  


sudo docker run --rm -i \
    -v $PWD:/vuls \
    -v $PWD/go-exploitdb-log:/var/log/go-exploitdb \
    vuls/go-exploitdb fetch exploitdb

sudo docker run --rm -i \
    -v $PWD:/vuls \
    -v $PWD/go-msfdb-log:/var/log/go-msfdb \
    vuls/go-msfdb fetch msfdb

    
touch /home/ubuntu/A3.txt

touch config_scan.toml

cat > config_scan.toml <<EOF
[servers]
[servers.host]
host        = "172.17.0.1"
port        = "2222"
user        = "root"
sshConfigPath = "/root/.ssh/config"
keyPath     = "/root/.ssh/id_rsa_vuls"
scanMode    = ["fast-root", "offline"]
EOF

cat > config_db.toml <<EOF
[cveDict]
type = "sqlite3"
SQLite3Path = "/vuls/cve.sqlite3"

[ovalDict]
type = "sqlite3"
SQLite3Path = "/vuls/oval.sqlite3"

[gost]
type = "sqlite3"
SQLite3Path = "/vuls/gost.sqlite3"

[exploit]
type = "sqlite3"
SQLite3Path = "/vuls/go-exploitdb.sqlite3"

[metasploit]
type = "sqlite3"
SQLite3Path = "/vuls/go-msfdb.sqlite3"
EOF
touch /tmp/userData.finished
'''

script_b = '''
set -ex

touch /home/ubuntu/startB.txt

sudo mkdir -p /vol/
sudo mount {mount_point} /vol/


FILE="/vol/usr/sbin/sshd"
if [ -f "$FILE" ]; then
/bin/rm -f ~/.ssh/id_rsa_vuls
/bin/rm -f ~/.ssh/id_rsa_vuls.pub
ssh-keygen -q -f ~/.ssh/id_rsa_vuls -N ""
sudo cat ~/.ssh/id_rsa_vuls.pub > /tmp/tmp_authorized_keys
sudo mv /tmp/tmp_authorized_keys /vol/root/.ssh/tmp_authorized_keys
sudo chown root:root /vol/root/.ssh/tmp_authorized_keys
sudo chmod 600 /vol/root/.ssh/tmp_authorized_keys


sudo mount -t proc none /vol/proc
sudo mount -o bind /dev /vol/dev
sudo mount -o bind /sys /vol/sys
sudo mount -o bind /run /vol/run


sudo chroot /vol /bin/mount devpts /dev/pts -t devpts
# Reporting
mkdir -p /home/ubuntu/nginx/html
cat > /home/ubuntu/nginx/default.conf <<EOF
server {{
    listen       80;
    listen  [::]:80;
    server_name  localhost;

    #charset koi8-r;
    #access_log  /var/log/nginx/host.access.log  main;
    location /vuls/ {{
	proxy_pass http://172.18.0.1:8000/;
    }}
    location / {{
        root   /usr/share/nginx/html;
        index  index.html index.htm;
    }}

    #error_page  404              /404.html;

    # redirect server error pages to the static page /50x.html
    #
    error_page   500 502 503 504  /50x.html;
    location = /50x.html {{
        root   /usr/share/nginx/html;
    }}

    # proxy the PHP scripts to Apache listening on 127.0.0.1:80
    #
    #location ~ \.php$ {{
    #    proxy_pass   http://127.0.0.1;
    #}}

    # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
    #
    #location ~ \.php$ {{
    #    root           html;
    #    fastcgi_pass   127.0.0.1:9000;
    #    fastcgi_index  index.php;
    #    fastcgi_param  SCRIPT_FILENAME  /scripts$fastcgi_script_name;
    #    include        fastcgi_params;
    #}}

    # deny access to .htaccess files, if Apache's document root
    # concurs with nginx's one
    #
    #location ~ /\.ht {{
    #    deny  all;
    #}}
}}
EOF

cat > /home/ubuntu/nginx/html/index.html <<EOF
<!DOCTYPE html>
<html>

<head>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/css/bootstrap.min.css" integrity="sha512-tDXPcamuZsWWd6OsKFyH6nAqh/MjZ/5Yk88T5o+aMfygqNFPan1pLyPFAndRzmOWHKT+jSDzWpJv8krj6x1LMA==" crossorigin="anonymous" />
<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source Sans Pro">
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.5.1/jquery.min.js" integrity="sha512-bLT0Qm9VnAYZDflyKcBaQ2gg0hSYNQrJ8RilYldYQ1FxQYoCLtUjuuRuZo+fjqhx/qtq/1itJ0C2ejDxltZVFg==" crossorigin="anonymous"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/js/bootstrap.bundle.min.js" integrity="sha512-TqmAh0/sSbwSuVBODEagAoiUIeGRo8u95a41zykGfq5iPkO9oie8IKCgx7yAr1bfiBjZeuapjLgMdp9UMpCVYQ==" crossorigin="anonymous"></script>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light">
  <a class="navbar-brand" href="#">Red Detector</a>
  <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
    <span class="navbar-toggler-icon"></span>
  </button>

  <div class="collapse navbar-collapse" id="navbarSupportedContent">
    <ul class="navbar-nav mr-auto">
      <li class="nav-item">
        <a class="nav-link" href="#" onclick="javascript:document.getElementById('main').style.display = 'block';document.getElementById('frame').src='';document.getElementById('frame').style.display = 'none'">Home</a>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="#" onclick="javascript:document.getElementById('main').style.display = 'none';document.getElementById('frame').src='/vuls/';document.getElementById('frame').style.display = 'block'">Vuls</a>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="#" onclick="javascript:document.getElementById('main').style.display = 'none';document.getElementById('frame').src='lynis_report.html';document.getElementById('frame').style.display = 'block'">Lynis audit</a>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="#" onclick="javascript:document.getElementById('main').style.display = 'none';document.getElementById('frame').src='chkrootkit_report.html';document.getElementById('frame').style.display = 'block'">Chkrootkit report</a>
      </li>
    </ul>
  </div>
</nav>
<div id="main">
    <div class="container">
        <div class="row">
            <div class="col" style="text-align: center;">
                <img src="https://github.com/lightspin-tech/red-detector/raw/main/static/red-detector.png" style="margin: auto;">
            </div>
        </div>
        <div class="row">
            <div class="col" style="text-align: center;">
                <a href="https://lightspin.io">
                    <svg width="400px" xmlns="http://www.w3.org/2000/svg" height="100%" version="1.1" viewBox="0 0 432 72" xmlns:xlink="http://www.w3.org/1999/xlink">          <defs>         <linearGradient id="linearGradient-1" x1="100%" x2="0%" y1="50%" y2="50%">             <stop offset="20.0911%" stop-color="#00C4D3"></stop>             <stop offset="100%" stop-color="#18C8FF"></stop>         </linearGradient>     </defs>     <g id="Page-1" fill="none" stroke="none" fill-rule="evenodd" stroke-width="1">         <g id="Artboard" transform="translate(-215.000000, -354.000000)">             <g id="Group-25-(1)" transform="translate(215.000000, 354.000000)">                 <path d="M200.248665,18.8018551 C205.689408,18.8018551 209.96469,20.7106966 213.074511,24.5283795 L213.074511,24.5283795 L213.074511,19.8296928 L222.442719,19.8296928 L222.442719,51.9350388 L222.437596,52.5398199 C222.382958,55.7393507 221.89142,58.5234298 220.969346,60.8944787 C219.995187,63.3994572 218.63729,65.4480561 216.893867,67.0532309 C215.138764,68.7161176 212.99848,69.9358569 210.450345,70.7233327 L210.450345,70.7233327 L209.935223,70.8880734 C207.514317,71.6302563 204.854852,72 201.937255,72 C198.802995,72 195.567772,71.5242117 192.228803,70.5703466 L192.228803,70.5703466 L191.622434,70.3881808 C189.016829,69.5773924 186.697134,68.4883997 184.662318,67.1226899 L184.662318,67.1226899 L184.538437,67.036811 L189.355798,60.1637748 L189.715289,60.4432294 C191.239031,61.5949054 192.878806,62.4780318 194.631295,63.0895597 C196.880697,63.9073941 199.100381,64.3203827 201.276503,64.3203827 C205.064751,64.3203827 207.932801,63.2922713 209.808329,61.1952857 C211.69303,59.1500389 212.634009,56.434103 212.634009,53.1097105 L212.634009,53.1097105 L212.634009,49.901489 C209.594153,51.8080868 207.52773,53.0136139 206.434741,53.5180704 C204.663384,54.3356201 202.629447,54.7470097 200.322082,54.7470097 C197.670532,54.7470097 195.340868,54.2856508 193.323014,53.3687614 C191.307311,52.4063733 189.580834,51.1172623 188.153478,49.5061188 C186.779307,47.9027438 185.716288,46.0307667 184.973362,43.8957369 C184.228609,41.7061064 183.854553,39.3926233 183.854553,36.9579748 C183.854553,34.5233264 184.228609,32.2098432 184.975653,30.0135539 C185.720048,27.8278592 186.785457,25.9053406 188.173303,24.2399256 C189.588737,22.5967634 191.311985,21.2870943 193.340212,20.3189264 C195.366331,19.3063362 197.659384,18.8018551 200.248665,18.8018551 Z M342.667549,18.8018551 L342.667549,24.3081286 C345.582799,20.6372796 349.882553,18.8018551 355.566812,18.8018551 C358.063446,18.8018551 360.313143,19.2839666 362.328596,20.2455881 C364.352513,21.2116991 366.047583,22.5173003 367.421923,24.1665086 C368.862558,25.84044 369.948529,27.781182 370.691069,30.0078504 L370.691069,30.0078504 L370.868562,30.5204561 C371.549876,32.5775886 371.887507,34.7158661 371.887507,36.9579748 C371.887507,39.3942164 371.512947,41.734211 370.764364,43.9818839 C370.020692,46.2119428 368.931912,48.1808629 367.496904,49.8944027 C366.117229,51.5500082 364.416342,52.8830668 362.385258,53.8987984 C360.375729,54.9032813 358.082676,55.4077625 355.493395,55.4077625 C353.379842,55.4077625 351.388493,54.9957591 349.510461,54.1711195 C348.285976,53.6036956 346.200784,52.3273193 343.254885,50.3419909 L343.254885,50.3419909 L343.254885,72 L333.225924,72 L333.225924,18.8018551 L342.667549,18.8018551 Z M313.679,17.978 C316.349566,17.978 318.948227,18.4071097 321.47519,19.2654345 L321.47519,19.2654345 L321.951752,19.4219397 C323.995553,20.1214046 325.762655,21.0975039 327.262268,22.3523234 L327.262268,22.3523234 L327.561,22.61 L321.687,28.68 L321.35334,28.3965966 C320.506214,27.7020525 319.553018,27.0999867 318.494917,26.5905036 C317.113274,25.9252332 315.652136,25.592 314.117,25.592 C312.927853,25.592 311.810894,25.8257449 310.772759,26.2930656 C309.661917,26.8189619 309.091,27.7506154 309.091,29.012 C309.091,30.2397052 309.725993,31.1468379 310.92704,31.6615725 C311.318724,31.8217835 311.787174,31.9868843 312.333146,32.157237 L312.333146,32.157237 L312.904986,32.3293539 L313.528675,32.5050526 L314.20438,32.6844137 L314.93227,32.8675177 L315.712513,33.054445 L316.697111,33.2798378 C317.846061,33.5552599 318.99152,33.9176502 320.139222,34.3683948 C321.509992,34.8884685 322.731652,35.5696972 323.809789,36.4137079 C324.874994,37.2475953 325.730799,38.265129 326.378719,39.4689648 C327.018534,40.6577446 327.341,42.0854647 327.341,43.758 C327.341,45.9625288 326.89914,47.8233373 326.020728,49.3484502 C325.13806,50.8343931 323.976092,52.0430214 322.532985,52.9738202 C321.117293,53.9175142 319.517309,54.5998339 317.724747,55.0244645 C315.91351,55.453519 314.102174,55.668 312.292,55.668 C309.375168,55.668 306.506875,55.2138619 303.685287,54.3050765 L303.685287,54.3050765 L303.175813,54.1225903 C300.990897,53.3101637 299.102489,52.2162963 297.512548,50.8427037 L297.512548,50.8427037 L297.158,50.527 L303.169,44.189 L303.430471,44.4458741 C304.41561,45.3784235 305.567786,46.1742406 306.885347,46.8331906 C308.511752,47.6466017 310.243319,48.054 312.073,48.054 C313.121002,48.054 314.142946,47.8181666 315.13398,47.3488988 C316.290105,46.7707288 316.88,45.7680892 316.88,44.415 C316.88,43.0909719 316.174777,42.0918853 314.836317,41.4784627 C314.198668,41.186225 313.379247,40.8894315 312.376597,40.5871334 L312.376597,40.5871334 L311.681002,40.3847755 C311.440079,40.3170441 311.19009,40.2490305 310.931022,40.1807242 L310.931022,40.1807242 L310.12656,39.974917 L308.64506,39.6156459 C307.607845,39.3496842 306.571707,39.0176201 305.536541,38.6193472 C304.319598,38.1511366 303.221296,37.5202433 302.240591,36.7263714 C301.327033,35.9494209 300.564269,34.9786305 299.960561,33.818233 C299.367163,32.6776516 299.068,31.2965368 299.068,29.669 C299.068,27.5661791 299.507667,25.8072005 300.381261,24.3823453 C301.272268,22.882372 302.412506,21.6722226 303.809344,20.7410295 C305.221361,19.7997171 306.77453,19.1172556 308.471268,18.6930713 C310.239603,18.2152916 311.97181,17.978 313.679,17.978 Z M285.359743,10.2120684 L285.359743,19.8296928 L293.949529,19.8296928 L293.949529,26.8485572 L285.359743,26.8485572 L285.359743,41.8034955 L285.364054,42.1562294 C285.407222,43.8958342 285.775358,45.2742901 286.504713,46.2836342 C287.449285,47.4342666 288.931055,47.9483962 290.917307,47.9483962 C291.556778,47.9483962 292.21918,47.8953877 292.905528,47.7898875 L292.905528,47.7898875 L293.224491,47.7396168 L293.457736,47.6949567 L293.570376,54.4292047 L293.411069,54.4742117 C292.799389,54.6367023 292.088031,54.7809102 291.278236,54.9055484 C290.030179,55.1446934 288.821495,55.2609285 287.613543,55.2609285 C285.272072,55.2609285 283.327086,54.9830734 281.781358,54.4373024 C280.282554,53.8639589 279.068987,53.0695748 278.151277,52.0644937 C277.294355,51.0353081 276.65072,49.7921259 276.247639,48.3589772 C275.833778,46.8413696 275.62445,45.1434897 275.62445,43.2718351 L275.62445,43.2718351 L275.62445,26.8485572 L269.751091,26.8485572 L269.751091,19.8296928 L275.551033,19.8296928 L275.551033,10.2120684 L285.359743,10.2120684 Z M241.177806,4.41212699 L241.177806,24.4549626 C243.372786,20.6862242 247.256511,18.8018551 252.82898,18.8018551 C255.187685,18.8018551 257.091256,19.2085003 258.598937,20.006524 C260.185267,20.822588 261.433576,21.8702198 262.366213,23.1581159 L262.366213,23.1581159 L262.612219,23.4833755 C263.490348,24.6893713 264.106219,26.0434952 264.479482,27.5780479 L264.479482,27.5780479 L264.628249,28.1604222 C265.001287,29.7109123 265.185159,31.2421355 265.185159,32.773207 L265.185159,32.773207 L265.185159,54.3799248 L255.082781,54.3799248 L255.082781,35.5630522 L255.076333,35.0274322 C255.054837,34.1414049 254.97957,33.2887452 254.850224,32.4695251 C254.682376,31.40645 254.340757,30.4669962 253.821786,29.6597474 C253.384438,28.8318741 252.712031,28.1291119 251.859766,27.6419063 L251.859766,27.6419063 L251.650616,27.5157453 C250.864699,27.0729862 249.870879,26.8485572 248.71763,26.8485572 C246.303768,26.8485572 244.385775,27.7494229 243.064332,29.5310689 L243.064332,29.5310689 L242.860578,29.8082652 C241.738942,31.4004988 241.177806,33.3566727 241.177806,35.6364692 L241.177806,35.6364692 L241.177806,54.3799248 L231.148846,54.3799248 L231.148846,4.41212699 L241.177806,4.41212699 Z M406.840385,18.8018551 L406.840385,24.8954644 C409.450941,20.8330582 413.4815,18.8018551 418.932061,18.8018551 C421.227467,18.8018551 423.150859,19.2091781 424.712687,20.0120893 C426.288348,20.822588 427.536657,21.8702198 428.469294,23.1581159 L428.469294,23.1581159 L428.715287,23.4836253 C429.593404,24.6904906 430.209651,26.0449384 430.582563,27.5780479 L430.582563,27.5780479 L430.73126,28.1611908 C431.10416,29.71349 431.28824,31.2445835 431.28824,32.773207 L431.28824,32.773207 L431.28824,54.3799248 L421.185862,54.3799248 L421.185862,35.4162183 L421.177111,34.8732289 C421.147942,33.9745646 421.045844,33.107547 420.870766,32.2730385 C420.714941,31.2779892 420.407059,30.3546315 419.952271,29.5581095 C419.479591,28.672505 418.773181,27.9658735 417.863549,27.4807783 C417.072406,26.9687673 416.00423,26.7017233 414.747293,26.7017233 C413.511442,26.7017233 412.395488,26.9592513 411.413323,27.4794304 C410.506478,27.9323065 409.722285,28.6003327 409.090585,29.462278 C408.482601,30.290315 408.016536,31.2502578 407.690389,32.3373747 L407.690389,32.3373747 L407.580619,32.786889 C407.378545,33.6885927 407.280887,34.6074369 407.280887,35.5630522 L407.280887,35.5630522 L407.280887,54.3799248 L397.17851,54.3799248 L397.17851,18.8018551 L406.840385,18.8018551 Z M139.616296,4.41212699 L139.616296,45.4522189 L159.732549,45.4522189 L159.732549,54.3799248 L129,54.3799248 L129,4.41212699 L139.616296,4.41212699 Z M176.153815,19.8296928 L176.153815,54.3799248 L166.124855,54.3799248 L166.124855,19.8296928 L176.153815,19.8296928 Z M388.641342,18.8018551 L388.641342,54.3799248 L378.612382,54.3799248 L378.612382,18.8018551 L388.641342,18.8018551 Z M352.630133,27.6283063 C351.259347,27.6283063 350.035396,27.8975354 348.959284,28.4358931 C347.882166,28.9742508 346.951883,29.6839817 346.169439,30.5649855 C345.435269,31.4459893 344.847933,32.4493882 344.407431,33.5750817 C344.015203,34.7007752 343.820095,35.8510081 343.820095,37.0256798 C343.820095,38.2003514 344.015203,39.3505843 344.407431,40.4762778 C344.847933,41.6019713 345.435269,42.6053702 346.169439,43.486374 C346.951883,44.3673778 347.882166,45.0771088 348.959284,45.6154664 C350.035396,46.1538241 351.259347,46.4230532 352.630133,46.4230532 C354.049192,46.4230532 355.297281,46.1538241 356.374399,45.6154664 C357.450511,45.0771088 358.331514,44.3673778 359.01741,43.486374 C359.75158,42.6053702 360.289636,41.6019713 360.632584,40.4762778 C361.023806,39.3016061 361.219919,38.1269345 361.219919,36.9522628 C361.219919,35.7775911 361.023806,34.6273582 360.632584,33.5016647 C360.289636,32.3759712 359.75158,31.3970111 359.01741,30.5649855 C358.331514,29.6839817 357.450511,28.9742508 356.374399,28.4358931 C355.297281,27.8975354 354.049192,27.6283063 352.630133,27.6283063 Z M203.111927,27.6283063 C201.742147,27.6283063 200.518196,27.872996 199.441078,28.3624761 C198.41324,28.8519562 197.532237,29.512709 196.798067,30.3447346 C196.063897,31.1767602 195.501704,32.1557203 195.109476,33.2814138 C194.718254,34.4071073 194.52214,35.6063183 194.52214,36.8788458 C194.52214,38.1024957 194.718254,39.2771673 195.109476,40.4028608 C195.501704,41.5285543 196.063897,42.5319533 196.798067,43.412957 C197.532237,44.2449826 198.41324,44.9302748 199.441078,45.4686325 C200.518196,45.9581125 201.742147,46.2028023 203.111927,46.2028023 C204.482713,46.2028023 205.706664,45.9581125 206.782776,45.4686325 C207.909174,44.9302748 208.838452,44.2449826 209.572621,43.412957 C210.356071,42.5809314 210.943407,41.6019713 211.334629,40.4762778 C211.775131,39.3505843 211.995382,38.1513733 211.995382,36.8788458 C211.995382,35.6551959 211.775131,34.4805243 211.334629,33.3548308 C210.943407,32.2291372 210.356071,31.2501771 209.572621,30.4181515 C208.790177,29.5371478 207.859894,28.8519562 206.782776,28.3624761 C205.706664,27.872996 204.482713,27.6283063 203.111927,27.6283063 Z M171.123312,0 L178.23477,7.11145815 L171.123312,14.2229163 L164.011854,7.11145815 L171.123312,0 Z M383.76565,2.04281037e-13 L390.877108,7.11145815 L383.76565,14.2229163 L376.654192,7.11145815 L383.76565,2.04281037e-13 Z" id="Shape" fill="#010C31" fill-rule="nonzero"></path>                 <g id="Group">                     <path d="M48.0832,14.1421 L55.1543,21.2132 L62.2253,14.1421 L55.1543,7.0711 L62.2253,7.10542736e-15 L96.166,33.9411 L62.2253,67.8822 L55.1543,60.8112 L62.2253,53.7401 L55.1543,46.669 L48.0832,53.7401 L28.2842,33.9411 L48.0832,14.1421 Z M82.024,33.9411 L62.2253,14.1421 L42.4264,33.9411 L62.2253,53.7401 L82.024,33.9411 Z" id="Shape" fill="#010C31"></path>                     <path d="M48.0833,53.7401 L41.0122,46.669 L53.7402,33.9411 L41.0122,21.2132 L48.0833,14.1421 L67.8823,33.9411 L48.0833,53.7401 Z M41.0122,60.8112 L33.9412,67.8822 L5.68434189e-13,33.9411 L33.9412,7.10542736e-15 L41.0122,7.0711 L14.1422,33.9411 L41.0122,60.8112 Z" id="Shape" fill="url(#linearGradient-1)"></path>                 </g>                 <polygon id="Path" fill="#CFD5E4" points="48.0832 14.2844 55.1543 21.3555 62.2254 14.2844 55.1543 7.2133" fill-rule="nonzero"></polygon>                 <polygon id="Path" fill="#CFD5E4" points="48.0832 53.8821 55.1543 60.9531 62.2254 53.8821 55.1543 46.811" fill-rule="nonzero"></polygon>             </g>         </g>     </g> </svg>
                </a>
            </div>
        </div>
    </div>
</div>
<iframe src="" id="frame" style="width: 99vw; height: 95vh; border:0;">
</body>
</html>
EOF


sudo docker run --name docker-nginx -p {port}:80 -d -v /home/ubuntu/nginx/html:/usr/share/nginx/html -v /home/ubuntu/nginx/default.conf:/etc/nginx/conf.d/default.conf nginx


# Lynis audit
touch /home/ubuntu/bStartingLynis.txt
 

sudo cp /home/ubuntu/lynis-3.0.3.tar.gz /vol/root/


sudo su -c "chroot /vol tar xvf /root/lynis-3.0.3.tar.gz -C /root/"


sudo su -c "chroot /vol printf 'cd /root/lynis/\n./lynis audit system\n' > /vol/root/lynis/run.sh && chmod +x /vol/root/lynis/run.sh"


sudo su -c "chroot /vol lynis audit system" | ansi2html > /home/ubuntu/nginx/html/lynis_report.html


touch /home/ubuntu/bEndedLynis.txt
# Chkrootkit scan
cd /home/ubuntu/chkrootkit
# sudo ./chkrootkit -r /vol | sed -n '/INFECTED/,/Searching/p' | head -n -1 | ansi2html -l > /home/ubuntu/nginx/html/chkrootkit_report.html
sudo ./chkrootkit -r /vol | ansi2html -l > /home/ubuntu/nginx/html/chkrootkit_report.html


# Vuls scan

sudo su -c "chroot /vol /usr/sbin/sshd -p 2222 -o 'AuthorizedKeysFile=/root/.ssh/tmp_authorized_keys' -o 'AuthorizedKeysCommand=none' -o 'AuthorizedKeysCommandUser=none' -o 'GSSAPIAuthentication=no' -o 'UseDNS=no'"

touch /home/ubuntu/b1.txt

sudo cat > ~/.ssh/config <<EOF
Host *
    StrictHostKeyChecking no
EOF

touch /home/ubuntu/b2.txt

PWD=/home/ubuntu/vuls/
cd /home/ubuntu/vuls


sudo apt-get install debian-goodies -y

touch /home/ubuntu/b2-5.txt





echo "Scanning..."
sudo docker run --rm -i \
-v /home/ubuntu/.ssh:/root/.ssh:ro \
-v /home/ubuntu/vuls:/vuls \
-v /home/ubuntu/vuls/vuls-log:/var/log/vuls \
-v /etc/localtime:/etc/localtime:ro \
-v /etc/timezone:/etc/timezone:ro \
vuls/vuls scan \
-config=./config_scan.toml

touch /home/ubuntu/b3.txt

sudo docker run --rm -i \
    -v $PWD:/goval-dictionary \
    -v $PWD/goval-dictionary-log:/var/log/goval-dictionary \
    vuls/goval-dictionary fetch ubuntu 19 20
    
touch /home/ubuntu/b3_5.txt

sudo docker run --rm -i \
    -v /home/ubuntu/.ssh:/root/.ssh:ro \
    -v /home/ubuntu/vuls:/vuls \
    -v /home/ubuntu/vuls/vuls-log:/var/log/vuls \
    -v /etc/localtime:/etc/localtime:ro \
    vuls/vuls report \
    -format-list \
    -config=./config_db.toml

touch /home/ubuntu/b4.txt

touch /tmp/script.finished
sudo pkill -9 -f "/usr/sbin/sshd -p 2222" & sudo umount /vol/proc  & sudo umount /vol/sys & sudo umount /vol/run & sudo umount /vol/dev/pts & sudo umount /vol/dev & sudo umount {mount_point}
fi

touch /home/ubuntu/endofB.txt
'''

script_c = '''
touch /home/ubuntu/startC.txt
set -ex
echo "Starting report webUI..."

cd /home/ubuntu/vuls

sudo docker run -dt --name vuls-report-srv-{instance_id} \
    -v $PWD:/vuls \
    -p 8000:5111 \
    ishidaco/vulsrepo

echo "Check the report at: http://{ip_address}:{port}"
touch /home/ubuntu/endofC.txt
'''
