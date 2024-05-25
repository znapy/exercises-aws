## About

Exercises from [AWS Hands-on Tutorials](https://aws.amazon.com/getting-started/hands-on/) automated in aws-cli v2.

### Build a [Serverless Web Application](https://aws.amazon.com/getting-started/hands-on/build-serverless-web-app-lambda-apigateway-s3-dynamodb-cognito/)

Cost: Free if you have active of the Free Tier.

This exercise is located in the directory *\<project directory\>/aws-serverless-web-app*

The script `install.sh` uses environment variables from the *\<project directory\>/**.env*** file.

List of evironments (fill the empty values):

```
PROJECTNAME="aws-serverless-web-app"
IAM_USER="exercise"
IAM_USER_MAIL=""
REGION=""
```

where:
- **IAM_USER** - the name for a non-admin exercise user. The IAM user will be created with this name by script. His rights will change at different stages of script.
- **IAM_USER_MAIL** used for [email identity and verify procedure](https://docs.aws.amazon.com/ses/latest/dg/creating-identities.html#verify-email-addresses-procedure) - fill a real email address.
- **REGION** used as AWS Region - fill your nearest region, something like "us-east-1" or "eu-central-1".

To start container: `bash install.sh $AWS_ACCESS_KEY_ID $AWS_SECRET_ACCESS_KEY` with administrator keys.

I know about [boto3 module](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) for python,
but I don't want to install python3-pip for it, so I will use aws-cli and some code from pycognito for this module.

### Additional sources copied to this repository

- *wildrydes-site.tar.gz* from [s3://ttt-wildrydes/wildrydes-site](s3://ttt-wildrydes/wildrydes-site)
- some functions from [pycognito-2024.2.0/pycognito/aws_srp.py](https://pypi.org/project/pycognito/#files)
