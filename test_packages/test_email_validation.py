from email_validator import validate_email, EmailNotValidError
import unittest
def check_email(email):
    try:
        emailinfo = validate_email(email)
        return emailinfo.normalized
    except EmailNotValidError as e: 
        print(e)
    return


def test_invalid_email():
    email = "Notanemail"
    emailinfo = check_email(email)
    assert emailinfo != email

def test_valid_email():
    email = "mahdiash@buffalo.edu" 
    emailinfo = check_email(email)
    assert emailinfo == email

def test_invalid_domain():
    email = "mahdiash@buffadfdlo.edu"
    emailinfo = check_email(email)
    assert emailinfo != email


if __name__=="__main__":
    test_invalid_email() 
    test_valid_email()
    test_invalid_domain()
