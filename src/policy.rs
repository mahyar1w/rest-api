//! Every authorization rule lives here. These are pure functions with no database access,
//! so they are easy to unit-test and easy to explain.

use uuid::Uuid;

use crate::{extract::AuthUser, models::Role};

pub struct ProjectCtx {
    pub owner_id: Uuid,
    pub is_member: bool,
}

pub struct TaskCtx {
    pub assignee_id: Option<Uuid>,
}

pub fn can_create_project(u: &AuthUser) -> bool {
    matches!(u.role, Role::Admin | Role::Manager)
}

pub fn can_view_project(u: &AuthUser, p: &ProjectCtx) -> bool {
    u.role == Role::Admin || p.owner_id == u.id || p.is_member
}

/// Edit or delete the project, add or remove members, and create, edit or delete tasks.
pub fn can_manage_project(u: &AuthUser, p: &ProjectCtx) -> bool {
    u.role == Role::Admin || (u.role == Role::Manager && p.owner_id == u.id)
}

pub fn can_change_task_status(u: &AuthUser, p: &ProjectCtx, t: &TaskCtx) -> bool {
    can_manage_project(u, p) || t.assignee_id == Some(u.id)
}

pub fn is_admin(u: &AuthUser) -> bool {
    u.role == Role::Admin
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(role: Role) -> AuthUser {
        AuthUser {
            id: Uuid::new_v4(),
            role,
        }
    }

    fn project(owner: &AuthUser, is_member: bool) -> ProjectCtx {
        ProjectCtx {
            owner_id: owner.id,
            is_member,
        }
    }

    #[test]
    fn only_admins_and_managers_create_projects() {
        assert!(can_create_project(&user(Role::Admin)));
        assert!(can_create_project(&user(Role::Manager)));
        assert!(!can_create_project(&user(Role::Member)));
    }

    #[test]
    fn view_needs_admin_owner_or_membership() {
        let owner = user(Role::Manager);
        let stranger = user(Role::Manager);
        assert!(can_view_project(
            &user(Role::Admin),
            &project(&owner, false)
        ));
        assert!(can_view_project(&owner, &project(&owner, false)));
        assert!(can_view_project(
            &user(Role::Member),
            &project(&owner, true)
        ));
        assert!(!can_view_project(&stranger, &project(&owner, false)));
        assert!(!can_view_project(
            &user(Role::Member),
            &project(&owner, false)
        ));
    }

    #[test]
    fn manage_needs_admin_or_owning_manager() {
        let owner = user(Role::Manager);
        let other_manager = user(Role::Manager);
        // A member of the project can see it but not manage it, even a manager who is only a member.
        assert!(can_manage_project(
            &user(Role::Admin),
            &project(&owner, false)
        ));
        assert!(can_manage_project(&owner, &project(&owner, false)));
        assert!(!can_manage_project(&other_manager, &project(&owner, true)));
        assert!(!can_manage_project(
            &user(Role::Member),
            &project(&owner, true)
        ));
    }

    #[test]
    fn a_member_can_change_status_only_of_their_own_task() {
        let owner = user(Role::Manager);
        let member = user(Role::Member);
        let ctx = project(&owner, false);
        let mine = TaskCtx {
            assignee_id: Some(member.id),
        };
        let theirs = TaskCtx {
            assignee_id: Some(Uuid::new_v4()),
        };
        let nobody = TaskCtx { assignee_id: None };
        assert!(can_change_task_status(&member, &ctx, &mine));
        assert!(!can_change_task_status(&member, &ctx, &theirs));
        assert!(!can_change_task_status(&member, &ctx, &nobody));
        assert!(can_change_task_status(&owner, &ctx, &theirs));
    }
}
