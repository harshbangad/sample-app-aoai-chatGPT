import base64
import json

def get_authenticated_user_details(request_headers):
    user_object = {}

    ## check the headers for the Principal-Id (the guid of the signed in user)
    if "X-Ms-Client-Principal-Id" not in request_headers.keys():
        ## if it's not, assume we're in development mode and return a default user
        from . import sample_user
        raw_user_object = sample_user.sample_user
    else:
        ## if it is, get the user details from the EasyAuth headers
        raw_user_object = {k:v for k,v in request_headers.items()}

    user_object['user_principal_id'] = raw_user_object.get('X-Ms-Client-Principal-Id')
    user_object['user_name'] = raw_user_object.get('X-Ms-Client-Principal-Name')
    user_object['auth_provider'] = raw_user_object.get('X-Ms-Client-Principal-Idp')
    user_object['auth_token'] = raw_user_object.get('X-Ms-Token-Aad-Id-Token')
    user_object['client_principal_b64'] = raw_user_object.get('X-Ms-Client-Principal')
    user_object['aad_id_token'] = raw_user_object.get('X-Ms-Token-Aad-Id-Token')

    # ✅ NEW: Extract user groups from the client principal
    user_groups = []
    try:
        if user_object['client_principal_b64']:
            # Decode the base64 encoded client principal
            client_principal_json = base64.b64decode(user_object['client_principal_b64']).decode('utf-8')
            client_principal = json.loads(client_principal_json)
            
            # Extract claims which contain group information
            claims = client_principal.get('claims', [])
            
            # Find group claims (groups claim contains group names or IDs)
            for claim in claims:
                if claim.get('typ') == 'groups' or claim.get('typ') == 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups':
                    user_groups.append(claim.get('val'))
                # Also check for role claims as backup
                elif claim.get('typ') == 'roles' or claim.get('typ') == 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role':
                    user_groups.append(claim.get('val'))
            
            # Log for debugging
            import logging
            logging.debug(f"Extracted user groups: {user_groups}")
            logging.debug(f"All claims: {claims}")
    except Exception as e:
        import logging
        logging.exception(f"Error extracting user groups: {e}")
    
    user_object['user_groups'] = user_groups

    return user_object
