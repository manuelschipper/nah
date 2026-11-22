//! Registration for the AWS, Google Cloud, and Azure CLIs and their object store tools.
//! Provider dispatch delegates to the shared object store transfer, cloud scope,
//! remote command, and cloud resource delete models. Existing plan checks live in
//! `tests/suite/cloud_models.rs` and the storage and cloud decision corpus rows.

use crate::models::CommandModel;

use aws::AwsCommandModel;
use az::AzCommandModel;
use azcopy::AzcopyCommandModel;
use gcloud::GcloudCommandModel;
use gsutil::GsutilCommandModel;
use s3cmd::S3cmdCommandModel;

mod aws;
mod aws_ec2;
mod aws_request_input;
mod aws_s3;
mod az;
mod azcopy;
mod cloud_args;
mod cloud_coverage;
mod cloud_effects;
mod cloud_scope;
mod gcloud;
mod gsutil;
mod object_store_target;
mod object_store_transfer;
mod rclone;
mod remote_commands;
mod resource_delete;
mod s3cmd;

pub(super) use rclone::with_rclone_storage;

/// Register the cloud command models in their built-in registry order.
pub(super) fn cloud_models() -> Vec<Box<dyn CommandModel>> {
    vec![
        Box::new(AwsCommandModel),
        Box::new(GcloudCommandModel),
        Box::new(GsutilCommandModel),
        Box::new(AzCommandModel),
        Box::new(AzcopyCommandModel),
        Box::new(S3cmdCommandModel),
    ]
}
