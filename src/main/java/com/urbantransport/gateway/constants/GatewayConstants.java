package com.urbantransport.gateway.constants;

import java.util.List;

public final class GatewayConstants {

    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";

    /** Cabeceras que el gateway inyecta hacia los microservicios a partir del JWT. */
    public static final String USER_ID_HEADER = "X-User-Id";
    public static final String USER_ROLE_HEADER = "X-User-Role";
    public static final String BRANCH_ID_HEADER = "X-Branch-Id";
    public static final String CUSTOMER_ID_HEADER = "X-Customer-Id";
    public static final String CUSTOMER_NIT_HEADER = "X-Customer-Nit";

    /** Se eliminan de toda petición entrante para que nadie pueda suplantar su identidad. */
    public static final List<String> IDENTITY_HEADERS = List.of(
            USER_ID_HEADER,
            USER_ROLE_HEADER,
            BRANCH_ID_HEADER,
            CUSTOMER_ID_HEADER,
            CUSTOMER_NIT_HEADER
    );

    public static final String CLAIM_USER_ID = "user_id";
    public static final String CLAIM_SUB = "sub";
    public static final String CLAIM_ROLE = "role";
    public static final String CLAIM_ROLES = "roles";
    public static final String CLAIM_EXP = "exp";
    public static final String CLAIM_BRANCH_ID = "branchId";
    public static final String CLAIM_CUSTOMER_ID = "customerId";
    public static final String CLAIM_NIT = "nit";

    public static final String RS256_ALGORITHM = "RS256";
    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    private GatewayConstants() {
    }
}
