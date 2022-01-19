# A Mock Audio Server API


## Getting started

Steps:

1. Clone/pull/download this repository
- You'll need to have virtual enviroment installed on your machine  

    ```python
  pip3 install virtualenv
  
    ```


- Setup virtual environment

    ```markdown
    virtualenv -p python3 env
    
    ``` 

- Activate virtual environment

    ```markdown
    source env/bin/activate
    
    ```
    

   - Install requirements
    
        ```bash
        pip install -r requirements.txt
        ```



### Run migrations before starting the flask-server

#### Set up and configure database with the parameters in the DATABASE_URL in the config.py
#### or adjust to fit your own database details before proceeding to the next steps

```python
   python manage.py db init
```

```python
   python manage.py db migrate
```

```python
   python manage.py db upgrade
```

```python
   python manage.py runserver
```

## Audio File Type
### The 3 audio file type to use in audioFileType parameters are:
#### - song for Song file type
#### - podcast for Podcast file type
#### - audiobook for Audiobook file type

## Testing
```python
   pytest -v
```


