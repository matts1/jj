// Copyright 2020 The Jujutsu Authors
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

use itertools::Itertools;
use jj_lib::commit::Commit;
use jj_lib::repo::Repo;
use jj_lib::revset::{RevsetExpression, RevsetIteratorExt};

use crate::cli_util::{short_commit_hash, user_error, CommandError, CommandHelper};
use crate::ui::Ui;

/// Move the current working copy commit to the next child revision in the
/// repository.
///
///
/// The command moves you to the next child in a linear fashion.
///
///
/// D      D @
/// |      |/
/// C @ => C
/// |/     |
/// B      B
///
///
/// If `--edit` is passed, it will move you directly to the child
/// revision.
///
///
/// D    D
/// |    |
/// C    C
/// |    |
/// B => @
/// |    |
/// @    A
// TODO(#2126): Handle multiple child revisions properly.
#[derive(clap::Args, Clone, Debug)]
#[command(verbatim_doc_comment)]
pub(crate) struct NextArgs {
    /// How many revisions to move forward. By default advances to the next
    /// child.
    #[arg(default_value = "1")]
    amount: u64,
    /// Instead of creating a new working-copy commit on top of the target
    /// commit (like `jj new`), edit the target commit directly (like `jj
    /// edit`).
    #[arg(long)]
    edit: bool,
}

pub(crate) fn cmd_next(
    ui: &mut Ui,
    command: &CommandHelper,
    args: &NextArgs,
) -> Result<(), CommandError> {
    let mut workspace_command = command.workspace_helper(ui)?;
    let edit = args.edit;
    let amount = args.amount;
    let current_wc_id = workspace_command
        .get_wc_commit_id()
        .ok_or_else(|| user_error("This command requires a working copy"))?;
    let current_wc = workspace_command.repo().store().get_commit(current_wc_id)?;
    let current_short = short_commit_hash(current_wc.id());
    // If we're editing, start at the working-copy commit.
    // Otherwise start from our direct parent.
    let start_id = if edit {
        current_wc_id
    } else {
        match current_wc.parent_ids() {
            [parent_id] => parent_id,
            _ => return Err(user_error("Cannot run `jj next` on a merge commit")),
        }
    };
    let descendant_expression = RevsetExpression::commit(start_id.clone()).descendants_at(amount);
    let target_expression = if edit {
        descendant_expression
    } else {
        descendant_expression.minus(&RevsetExpression::commit(current_wc_id.clone()).descendants())
    };
    let targets: Vec<Commit> = target_expression
        .resolve(workspace_command.repo().as_ref())?
        .evaluate(workspace_command.repo().as_ref())?
        .iter()
        .commits(workspace_command.repo().store())
        .take(2)
        .try_collect()?;
    let target = match targets.as_slice() {
        [target] => target,
        [] => {
            // We found no descendant.
            return Err(user_error(format!(
                "No descendant found {amount} commit{} forward",
                if amount > 1 { "s" } else { "" }
            )));
        }
        _ => {
            // TODO(#2126) We currently cannot deal with multiple children, which result
            // from branches. Prompt the user for resolution.
            return Err(user_error("Ambiguous target commit"));
        }
    };
    let target_short = short_commit_hash(target.id());
    // We're editing, just move to the target commit.
    if edit {
        // We're editing, the target must be rewritable.
        workspace_command.check_rewritable([target])?;
        let mut tx = workspace_command
            .start_transaction(&format!("next: {current_short} -> editing {target_short}"));
        tx.edit(target)?;
        tx.finish(ui)?;
        return Ok(());
    }
    let mut tx =
        workspace_command.start_transaction(&format!("next: {current_short} -> {target_short}"));
    // Move the working-copy commit to the new parent.
    tx.check_out(target)?;
    tx.finish(ui)?;
    Ok(())
}
