/// RouteFlow Canonical Role Definitions, Legacy Normalization & Permission Fencing.
library;

/// Canonical roles supported by RouteFlow Mobile Distributor client.
enum CanonicalRole {
  sales,
  warehouse,
  delivery,
  admin;

  String get key => switch (this) {
        CanonicalRole.sales => 'SALES',
        CanonicalRole.warehouse => 'WAREHOUSE',
        CanonicalRole.delivery => 'DELIVERY',
        CanonicalRole.admin => 'ADMIN',
      };

  String get displayName => switch (this) {
        CanonicalRole.sales => 'Sales Representative',
        CanonicalRole.warehouse => 'Inventory & Warehouse',
        CanonicalRole.delivery => 'Delivery Executive',
        CanonicalRole.admin => 'Distributor Admin',
      };

  String get badgeLabel => switch (this) {
        CanonicalRole.sales => 'SALES',
        CanonicalRole.warehouse => 'WAREHOUSE',
        CanonicalRole.delivery => 'DELIVERY',
        CanonicalRole.admin => 'ADMIN',
      };

  /// Normalizes server-provided role strings and legacy aliases into canonical roles.
  /// Fails closed (returns null) for any unrecognized, unauthenticated, or unsupported role.
  static CanonicalRole? fromString(String? roleStr) {
    if (roleStr == null) return null;
    final normalized = roleStr.trim().toUpperCase();
    return switch (normalized) {
      'SALES' || 'SALESPERSON' || 'SALES_REP' => CanonicalRole.sales,
      'WAREHOUSE' || 'WAREHOUSE_MANAGER' || 'INVENTORY' || 'INVENTORY_MGR' =>
        CanonicalRole.warehouse,
      'DELIVERY' ||
      'DELIVERY_EXECUTIVE' ||
      'LOGISTICS' ||
      'DRIVER' ||
      'DELIVERY_DRIVER' =>
        CanonicalRole.delivery,
      'ADMIN' || 'DISTRIBUTOR_ADMIN' || 'OPERATIONS_ADMIN' =>
        CanonicalRole.admin,
      _ => null, // Unknown or unsupported roles must fail closed
    };
  }
}

/// Granular business permissions strictly enforced across role experiences.
enum RolePermission {
  // Sales permissions
  viewAssignedRetailers,
  createSalesOrders,
  viewOrderHistory,
  viewAssignedBeat,
  recordVisitCheckIn,

  // Warehouse permissions
  viewGodownStock,
  recordInwardStock,
  adjustGodownStock,
  pickAndPackOrders,
  vehicleStockLoading,

  // Delivery permissions
  viewAssignedTrips,
  viewDeliveryStops,
  verifyDeliveryOtp,
  recordCashCollection,
  recordCashHandover,

  // Admin permissions
  viewOrgOverview,
  manageProducts,
  manageRetailers,
  manageEmployees,
  reviewOrderApprovals,
  viewReports,
}

/// Authoritative permission check matrix.
bool roleHasPermission(CanonicalRole role, RolePermission permission) {
  switch (role) {
    case CanonicalRole.sales:
      return permission == RolePermission.viewAssignedRetailers ||
          permission == RolePermission.createSalesOrders ||
          permission == RolePermission.viewOrderHistory ||
          permission == RolePermission.viewAssignedBeat ||
          permission == RolePermission.recordVisitCheckIn;

    case CanonicalRole.warehouse:
      return permission == RolePermission.viewGodownStock ||
          permission == RolePermission.recordInwardStock ||
          permission == RolePermission.adjustGodownStock ||
          permission == RolePermission.pickAndPackOrders ||
          permission == RolePermission.vehicleStockLoading;

    case CanonicalRole.delivery:
      return permission == RolePermission.viewAssignedTrips ||
          permission == RolePermission.viewDeliveryStops ||
          permission == RolePermission.verifyDeliveryOtp ||
          permission == RolePermission.recordCashCollection ||
          permission == RolePermission.recordCashHandover;

    case CanonicalRole.admin:
      // Admin has organization-wide operational oversight
      return permission == RolePermission.viewOrgOverview ||
          permission == RolePermission.manageProducts ||
          permission == RolePermission.manageRetailers ||
          permission == RolePermission.manageEmployees ||
          permission == RolePermission.reviewOrderApprovals ||
          permission == RolePermission.viewGodownStock ||
          permission == RolePermission.viewReports ||
          permission == RolePermission.viewOrderHistory;
  }
}

/// Throws an authorization exception if the role lacks the required permission.
void assertRolePermission(CanonicalRole role, RolePermission permission) {
  if (!roleHasPermission(role, permission)) {
    throw RoleAuthorizationException(
      'Role ${role.key} is not authorized for permission ${permission.name}.',
    );
  }
}

/// Exception thrown when an action violates server-authoritative role permissions.
class RoleAuthorizationException implements Exception {
  final String message;
  const RoleAuthorizationException(this.message);

  @override
  String toString() => 'RoleAuthorizationException: $message';
}
