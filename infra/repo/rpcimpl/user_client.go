package rpcimpl

import (
	"context"

	kiterrors "github.com/quocdaitrn/golang-kit/errors"

	"github.com/quocdaitrn/cp-auth/domain/repo/rpc"
	"github.com/quocdaitrn/cp-auth/proto/pb"
)

type rpcClient struct {
	client pb.UserServiceClient
}

// NewUserRepo creates and returns a user repository to interact with user's domain.
func NewUserRepo(client pb.UserServiceClient) rpc.UserRepo {
	return &rpcClient{client: client}
}

// CreateUser creates a new user.
func (c *rpcClient) CreateUser(ctx context.Context, firstName, lastName, email string) (newId uint, err error) {
	resp, err := c.client.CreateUser(ctx, &pb.CreateUserRequest{
		FirstName: firstName,
		LastName:  lastName,
		Email:     email,
	})
	if err != nil {
		return 0, kiterrors.WithStack(err)
	}

	return uint(resp.Id), nil
}
