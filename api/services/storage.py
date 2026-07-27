# api/services/storage.py
import boto3
from botocore.exceptions import ClientError
import os
import logging

logger = logging.getLogger(__name__)

# Tên bucket
BUCKET_CRX = "crx"
BUCKET_REPORTS = "reports"
BUCKET_PCAP = "pcap"
BUCKET_SCREENSHOTS = "screenshots"

ALL_BUCKETS = [BUCKET_CRX, BUCKET_REPORTS, BUCKET_PCAP, BUCKET_SCREENSHOTS]


def get_s3_client():
    """Create boto3 S3 client connected to MinIO."""
    return boto3.client(
        's3',
        endpoint_url=os.environ.get("S3_ENDPOINT", "http://minio:9000"),
        aws_access_key_id=os.environ.get("S3_ACCESS_KEY", "minioadmin"),
        aws_secret_access_key=os.environ.get("S3_SECRET_KEY", "minioadmin123"),
        region_name="us-east-1"  # MinIO không care nhưng boto3 cần value
    )


def ensure_buckets_exist():
    """Create all required buckets if they don't exist."""
    s3 = get_s3_client()
    for bucket_name in ALL_BUCKETS:
        try:
            s3.head_bucket(Bucket=bucket_name)
            logger.info(f"Bucket '{bucket_name}' already exists")
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ('404', 'NoSuchBucket'):
                s3.create_bucket(Bucket=bucket_name)
                logger.info(f"Created bucket '{bucket_name}'")
            else:
                logger.error(f"Error checking bucket '{bucket_name}': {e}")
                raise


def upload_file_bytes(bucket: str, key: str, content: bytes, content_type: str = "application/octet-stream"):
    """Upload bytes to MinIO."""
    s3 = get_s3_client()
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=content,
        ContentType=content_type
    )
    return f"s3://{bucket}/{key}"


def download_file_bytes(bucket: str, key: str) -> bytes:
    """Download object from MinIO as bytes."""
    s3 = get_s3_client()
    response = s3.get_object(Bucket=bucket, Key=key)
    return response['Body'].read()


def generate_presigned_url(bucket: str, key: str, expires_in: int = 3600) -> str:
    """Generate temporary URL for client to download directly."""
    s3 = get_s3_client()
    return s3.generate_presigned_url(
        'get_object',
        Params={'Bucket': bucket, 'Key': key},
        ExpiresIn=expires_in
    )


def check_object_exists(bucket: str, key: str) -> bool:
    """Check if object exists without downloading."""
    s3 = get_s3_client()
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError:
        return False