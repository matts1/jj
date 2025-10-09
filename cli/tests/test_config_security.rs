// Copyright 2024 The Jujutsu Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::path::Path;

use jj_lib::user_config::REPO_CONFIG_FILE;
use jj_lib::user_config::WORKSPACE_CONFIG_FILE;

use crate::common::TestEnvironment;
use crate::common::force_interactive;

fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dst.join(entry.file_name()))?;
        } else {
            std::fs::copy(entry.path(), dst.join(entry.file_name()))?;
        }
    }
    Ok(())
}

// Here we simulate a non malicious user attempting to send you a zip file
// containing no config.
#[test]
fn test_no_configs() {
    let sender_env = TestEnvironment::default();
    let work_dir = sender_env.work_dir("").create_dir("repo");
    sender_env.run_jj_in(".", ["git", "init", "repo"]).success();

    let d = work_dir.root().canonicalize().unwrap();
    let receiver_env = TestEnvironment::default();
    let output = receiver_env.run_jj_in(&d, ["status"]);
    insta::assert_snapshot!(output, @r###"
    The working copy has no changes.
    Working copy  (@) : qpvuntsm e8849ae1 (empty) (no description set)
    Parent commit (@-): zzzzzzzz 00000000 (empty) (no description set)
    [EOF]
    "###);
}

// Here we simulate an attacker attempting to send you a zip file containing a
// malicious jj repo
#[test]
fn test_attacker_without_signature() {
    // A test environment representing the user under attack.
    let victim_env = TestEnvironment::default();
    // A test environment with a different home directory, representing a malicious
    // actor.
    let evil_env = TestEnvironment::default();
    let work_dir = evil_env.work_dir("").create_dir("repo");
    evil_env.run_jj_in(".", ["git", "init", "repo"]).success();

    let d = work_dir.root().canonicalize().unwrap();
    evil_env
        .run_jj_in(&d, ["config", "set", "--repo", "test.key", "val"])
        .success();
    let output = victim_env.run_jj_in(&d, ["config", "list", "test"]);
    insta::assert_snapshot!(output, @r###"
    ------- stderr -------
    Error: The repo appears to have been created by someone else. For security reasons, we don't trust your repo config
    Hint: Run `jj config edit --repo` to review and re-enable
    [EOF]
    [exit status: 1]
    "###);
}

// Here, we simulate you having sent the attacker a zip file.
// They then send you another repo with that signature and you download it to a
// different directory.
fn repo_moved_fixture() -> TestEnvironment {
    let test_env = TestEnvironment::default();
    let repo_dir = test_env.work_dir("").create_dir("repo");
    test_env.run_jj_in(".", ["git", "init", "repo"]).success();

    let evil_dir = test_env.work_dir("copy");
    copy_dir_all(repo_dir.root(), evil_dir.root()).unwrap();

    // The file has moved but there's no config, so we consider it safe.
    evil_dir.run_jj(["status"]).success();

    repo_dir
        .run_jj(["config", "set", "--repo", "test.repo", "r"])
        .success();
    repo_dir
        .run_jj(["config", "set", "--workspace", "test.workspace", "w"])
        .success();

    std::fs::remove_dir_all(evil_dir.root()).unwrap();
    copy_dir_all(repo_dir.root(), evil_dir.root()).unwrap();
    test_env
}

#[test]
fn test_repo_moved_non_interactive() {
    let mut test_env = repo_moved_fixture();
    let edit_script = test_env.set_up_fake_editor();
    let copy = test_env.work_dir("copy");

    let output = copy.run_jj(["config", "list", "test"]);
    insta::assert_snapshot!(output, @r###"
    ------- stderr -------
    Error: The repo has moved from $TEST_ENV/repo/.jj/repo to $TEST_ENV/copy/.jj/repo. For security reasons, we don't trust your repo config
    Hint: Run `jj config edit --repo` to review and re-enable
    [EOF]
    [exit status: 1]
    "###);

    // The victim now reviews the repo config and finds it to not be a security
    // risk.
    copy.run_jj(["config", "edit", "--repo"]).success();

    let output = copy.run_jj(["config", "list", "test"]);
    insta::assert_snapshot!(output, @r###"
    ------- stderr -------
    Error: The workspace has moved from $TEST_ENV/repo/.jj to $TEST_ENV/copy/.jj. For security reasons, we don't trust your workspace config
    Hint: Run `jj config edit --workspace` to review and re-enable
    [EOF]
    [exit status: 1]
    "###);

    // The victim now reviews the workspace config and finds it to be a security
    // risk, so makes some changes.
    std::fs::write(&edit_script, "write\ntest.workspace = \"updated\"").unwrap();
    copy.run_jj(["config", "edit", "--workspace"]).success();
    let output = copy.run_jj(["config", "list", "test"]);
    insta::assert_snapshot!(output, @r###"
    test.repo = "r"
    test.workspace = "updated"
    [EOF]
    "###);
}

#[test]
fn test_repo_moved_review_config() {
    let mut test_env = repo_moved_fixture();
    let edit_script = test_env.set_up_fake_editor();
    let copy = test_env.work_dir("copy");

    std::fs::write(&edit_script, "write\ntest.key = \"val\"").unwrap();
    let output = copy.run_jj_with(|cmd| {
        force_interactive(cmd)
            .args(["config", "list", "test"])
            .write_stdin("r\nr\n")
    });
    insta::assert_snapshot!(output, @r###"
    test.key = "val"
    [EOF]
    ------- stderr -------
    Warning: The repo has moved from $TEST_ENV/repo/.jj/repo to $TEST_ENV/copy/.jj/repo. For security reasons, we don't trust your repo config
    There are several things you can do with this config:
      (r): Review the config and make any changes required to make it safe
      (t): Trust the config
      (d): Delete the config
    Please select an option: Editing file: $TEST_ENV/copy/.jj/repo/config.toml
    Warning: The workspace has moved from $TEST_ENV/repo/.jj to $TEST_ENV/copy/.jj. For security reasons, we don't trust your workspace config
    There are several things you can do with this config:
      (r): Review the config and make any changes required to make it safe
      (t): Trust the config
      (d): Delete the config
    Please select an option: Editing file: $TEST_ENV/copy/.jj/workspace-config.toml
    [EOF]
    "###);
}

#[test]
fn test_repo_moved_trust_config() {
    let test_env = repo_moved_fixture();
    let copy = test_env.work_dir("copy");

    let output = copy.run_jj_with(|cmd| {
        force_interactive(cmd)
            .args(["config", "list", "test"])
            .write_stdin("t\nt\n")
    });
    insta::assert_snapshot!(output, @r###"
    test.repo = "r"
    test.workspace = "w"
    [EOF]
    ------- stderr -------
    Warning: The repo has moved from $TEST_ENV/repo/.jj/repo to $TEST_ENV/copy/.jj/repo. For security reasons, we don't trust your repo config
    There are several things you can do with this config:
      (r): Review the config and make any changes required to make it safe
      (t): Trust the config
      (d): Delete the config
    Please select an option: Warning: The workspace has moved from $TEST_ENV/repo/.jj to $TEST_ENV/copy/.jj. For security reasons, we don't trust your workspace config
    There are several things you can do with this config:
      (r): Review the config and make any changes required to make it safe
      (t): Trust the config
      (d): Delete the config
    Please select an option: [EOF]
    "###);
}

#[test]
fn test_repo_moved_delete_config() {
    let test_env = repo_moved_fixture();
    let copy = test_env.work_dir("copy");

    let output = copy.run_jj_with(|cmd| {
        force_interactive(cmd)
            .args(["config", "list", "test"])
            .write_stdin("d\nd\n")
    });
    insta::assert_snapshot!(output, @r###"
    ------- stderr -------
    Warning: The repo has moved from $TEST_ENV/repo/.jj/repo to $TEST_ENV/copy/.jj/repo. For security reasons, we don't trust your repo config
    There are several things you can do with this config:
      (r): Review the config and make any changes required to make it safe
      (t): Trust the config
      (d): Delete the config
    Please select an option: Warning: The workspace has moved from $TEST_ENV/repo/.jj to $TEST_ENV/copy/.jj. For security reasons, we don't trust your workspace config
    There are several things you can do with this config:
      (r): Review the config and make any changes required to make it safe
      (t): Trust the config
      (d): Delete the config
    Please select an option: Warning: No matching config key for test
    [EOF]
    "###);
}

#[test]
fn test_legacy_config_migration() {
    let test_env = TestEnvironment::default();
    let repo_dir = test_env.work_dir("").create_dir("repo");
    repo_dir.run_jj(["git", "init"]).success();
    repo_dir
        .run_jj(["config", "set", "--repo", "repo-key", "repo-val"])
        .success();
    repo_dir
        .run_jj([
            "config",
            "set",
            "--workspace",
            "workspace-key",
            "workspace-val",
        ])
        .success();

    let repo_config_file = repo_dir.root().join(".jj/repo").join(REPO_CONFIG_FILE);
    std::fs::remove_file(&repo_config_file).unwrap();
    let workspace_config_file = repo_dir.root().join(".jj").join(WORKSPACE_CONFIG_FILE);
    std::fs::remove_file(&workspace_config_file).unwrap();

    let output = repo_dir.run_jj(["status"]);
    insta::assert_snapshot!(output, @r###"
    The working copy has no changes.
    Working copy  (@) : qpvuntsm e8849ae1 (empty) (no description set)
    Parent commit (@-): zzzzzzzz 00000000 (empty) (no description set)
    [EOF]
    "###);

    assert!(repo_config_file.exists());
    assert!(workspace_config_file.exists());
}
