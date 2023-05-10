#!/bin/sh

mockery --output=domain/service/serviceimpl/mock --outpkg=mock --dir=domain/service/ --case=snake --name=.*Service$
mockery --output=domain/service/serviceimpl/mock --outpkg=mock --dir=domain/service/ --case=snake --name=Hasher

mockery --output=domain/service/serviceimpl/mock --outpkg=mock --dir=domain/repo/store/ --case=snake --name=.*Repo$
mockery --output=domain/service/serviceimpl/mock --outpkg=mock --dir=domain/repo/rpc/ --case=snake --name=.*Repo$

mockery --output=domain/service/serviceimpl/mock --outpkg=mock --dir=vendor/github.com/quocdaitrn/golang-kit/auth/ --case=snake --name=JWTProvider