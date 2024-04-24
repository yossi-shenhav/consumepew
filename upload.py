import boto3
import os
import zipfile
from config1 import BUCKET_URL

#BUCKET_URL = 'https://pewpewscanresults.s3.amazonwas.com/'

def upload_zip_to_s3(tid):
    #create local zip file
    create_zip_from_directory('consume_lib/' + tid, zip_files_dir + "/" + tid + ".zip")
    b = upload_file_to_s3(zip_files_dir + "/" + tid + ".zip", BUCKET_URL, tid + ".zip" )
    return b
    

def upload_file_to_s3(file_name, object_name, bucket_name = None):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket_name: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """

    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = BUCKET_URL

    # Create S3 client
    s3_client = boto3.client('s3')

    try:
        response = s3_client.upload_file(file_name, bucket_name, object_name)
    except Exception as e:
        print(f"Error uploading file: {e}")
        return False
    return True

# Example usage:
#file_to_upload = 'path_to_your_file.txt'
#bucket_name = 'your_bucket_name'
#s3_object_name = 'file.txt'  # Optional, if not provided, it will use the same name as file_to_upload

#upload_successful = upload_file_to_s3(file_to_upload, bucket_name, s3_object_name)
#if upload_successful:
#    print("File uploaded successfully.")
#else:
#    print("Failed to upload file.")



def create_zip_from_directory(directory_path, zip_file_name):
    """Create a zip file from all the files in a directory

    :param directory_path: Path to the directory containing files to be zipped
    :param zip_file_name: Name of the zip file to be created
    :return: True if zip file was created successfully, else False
    """

    # Check if the directory exists
    if not os.path.isdir(directory_path):
        print(f"Error: '{directory_path}' is not a valid directory.")
        return False

    try:
        with zipfile.ZipFile(zip_file_name, 'w') as zipf:
            # Walk through each file in the directory and add it to the zip file
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    zipf.write(file_path, os.path.relpath(file_path, directory_path))
    except Exception as e:
        print(f"Error creating zip file: {e}")
        return False
    return True

# Example usage:
if __name__ == "__main__":
    directory_path = '/home/test1'
    zip_file_name = '69245691256912691679.zip'

if create_zip_from_directory(directory_path, zip_file_name):
    print(f"Zip file '{zip_file_name}' created successfully.")
    upload_file_to_s3('69245691256912691679.zip', BUCKET_URL)
else:
    print("Failed to create zip file.")
