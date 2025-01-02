FROM ubuntu

RUN sed -i -e 's/^# deb-src/deb-src/' /etc/apt/sources.list 
RUN apt-get update 
RUN apt-get upgrade --assume-yes  
RUN DEBIAN_FRONTEND=noninteractive apt-get install --assume-yes --no-install-recommends tzdata 
RUN apt-get build-dep --assume-yes openssh-server
RUN apt-get install --assume-yes build-essential fakeroot devscripts
RUN mkdir src && cd src
RUN apt-get source openssh-server
RUN ls -alh
RUN cd openssh-8.9p1/ && sed -e 's/^\([ \t]*\)\(struct passwd \*pw = authctxt->pw;\)/\1logit("Login attempt by username '\''%s'\'', password '\''%s'\'', from ip '\''%.200s'\''", authctxt->user, password, ssh_remote_ipaddr(ssh));\nreturn 0;\1\2/' -i auth-passwd.c && \
    debchange --nmu 'add verbose logging of usernames and passwords' && \
    EDITOR=true dpkg-source --commit . 'chatty-ssh.patch' && \
    debuild -us -uc -i -I && \
    apt-get install --assume-yes putty-tools python3-twisted && \
    debi && \
    mkdir /run/sshd && \
    cd && rm -rf /src && \
    apt-get clean && \
    apt-get autoremove --assume-yes 

RUN apt-get install --assume-yes python3-pip
WORKDIR /code
ADD requirements.txt /code/
RUN pip install -r requirements.txt
RUN touch /var/log/ssh.log

COPY monitor.py /code/

EXPOSE 22

CMD python3 monitor.py
