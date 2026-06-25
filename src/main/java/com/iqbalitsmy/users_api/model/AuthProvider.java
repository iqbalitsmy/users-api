package com.iqbalitsmy.users_api.model;

/**
 * ================================================================
 * AUTH PROVIDER ENUM
 * ================================================================
 * <p>
 * WHY an enum for the provider?
 * Type safety — we can't accidentally store "Gooogle" (typo) in the DB.
 * The compiler enforces valid values. Readable in code and in DB.
 * <p>
 * Adding a new provider (Facebook, Apple) = add one value here.
 * All switch/if checks will highlight the unhandled case automatically.
 * <p>
 * INTERVIEW TIP — "Why EnumType.STRING over EnumType.ORDINAL?"
 * ORDINAL stores the array index (LOCAL=0, GOOGLE=1, GITHUB=2).
 * If you INSERT a new enum value between existing ones, all ordinals shift.
 * Existing DB rows now point to the WRONG provider — silent data corruption.
 * STRING stores the name literally ("GOOGLE") — order-independent and safe.
 */
public enum AuthProvider {
    LOCAL,
    GOOGLE,
    GITHUB
}
