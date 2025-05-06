package de.twenty20.cmp

/**
 *
 * @author Joscha Vack - twenty20
 */

/**
 * Base exception
 */
class CmpClientException : Exception {
    constructor(message: String) : super(message)
    constructor(message: String, cause: Throwable) : super(message, cause)
}