package com.urbantransport.gateway.security;

/**
 * Identidad extraída de un JWT ya verificado.
 *
 * @param userId     id del usuario (claim user_id o sub)
 * @param role       rol del usuario
 * @param branchId   sucursal, solo para BRANCH_ADMIN y CASHIER (puede ser null)
 * @param customerId id del cliente, solo para CUSTOMER (puede ser null)
 * @param nit        NIT del cliente, solo para CUSTOMER (puede ser null)
 */
public record AuthenticatedUser(String userId, String role, String branchId, String customerId, String nit) {
}
