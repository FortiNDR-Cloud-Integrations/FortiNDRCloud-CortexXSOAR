
FROM demisto/python3:3.10.13.87159

COPY requirements.txt .
COPY com_fortinet_fndrc_integrations_python_client-1.0.3.tar.gz .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN pip install com_fortinet_fndrc_integrations_python_client-1.0.3.tar.gz
