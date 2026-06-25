package r2

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const keyPrefix = "potpuri/"

// Store implements ports.BlobContentStore against Cloudflare R2 (S3-compatible).
// Blobs are stored under "potpuri/{blobID}" so the bucket can be shared with
// other projects without key collisions.
type Store struct {
	client *s3.Client
	bucket string
}

type Config struct {
	AccountID       string
	AccessKeyID     string
	SecretAccessKey string
	Bucket          string
}

func Open(cfg Config) *Store {
	endpoint := fmt.Sprintf("https://%s.r2.cloudflarestorage.com", cfg.AccountID)
	client := s3.New(s3.Options{
		BaseEndpoint: aws.String(endpoint),
		Region:       "auto",
		Credentials:  credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
	})
	return &Store{client: client, bucket: cfg.Bucket}
}

func (s *Store) PutBlobContent(ctx context.Context, blobID string, ciphertext []byte) error {
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(keyPrefix + blobID),
		Body:          bytes.NewReader(ciphertext),
		ContentLength: aws.Int64(int64(len(ciphertext))),
	})
	return err
}

func (s *Store) GetBlobContent(ctx context.Context, blobID string) ([]byte, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(keyPrefix + blobID),
	})
	if err != nil {
		return nil, err
	}
	defer out.Body.Close()
	return io.ReadAll(out.Body)
}

func (s *Store) DeleteBlobContent(ctx context.Context, blobID string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(keyPrefix + blobID),
	})
	return err
}
