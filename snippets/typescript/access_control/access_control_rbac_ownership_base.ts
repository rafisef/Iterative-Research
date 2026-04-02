// ACCESS CONTROL
// Checks both role level AND resource ownership before granting access.
// Non-admins can only touch their own stuff. Role hierarchy is numeric
// so it's easy to compare without a bunch of if/else chains.

type Role = "admin" | "manager" | "user";

const ROLE_LEVEL: Record<Role, number> = { admin: 3, manager: 2, user: 1 };

function checkAccess(
  userRole: Role,
  userId: string,
  resourceOwnerId: string,
  requiredRole: Role
): void {
  if (ROLE_LEVEL[userRole] < ROLE_LEVEL[requiredRole]) {
    throw new Error("Forbidden");
  }
  if (userRole !== "admin" && resourceOwnerId !== userId) {
    throw new Error("Forbidden");
  }
}
