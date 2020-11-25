#include "stdafx.h"
#include "pch_script.h"
#include "script_game_object.h"

extern PCSTR scriptGameObjectLuaBindName;
extern PCSTR fVectorLuaBindName;

shared_str DumpLuaBindUserdata(const luabind::detail::object_rep* obj)
{
    string256 buffer;
    const void* const rawPtr = obj->get_instance(obj->crep()->classes().get(obj->crep()->type())).first;
    PCSTR luaBindName = obj->crep()->name();
    if (luaBindName == scriptGameObjectLuaBindName)
    {
        const auto* gameObject = &static_cast<const CScriptGameObject*>(rawPtr)->object();
        if (const auto* stalker = smart_cast<const CAI_Stalker*>(gameObject))
        {
            xr_sprintf(buffer, "CAI_Stalker[%s][%s]", stalker->CGameObject::Name(), stalker->Name());
        }
        else
        {
            xr_sprintf(buffer, "CGameObject[%s]", gameObject->Name());
        }
    }
	else if(luaBindName == fVectorLuaBindName)
	{  
		const auto* vector = static_cast<const Fvector*>(rawPtr);
		xr_sprintf(buffer, "Fvector[%2f,%2f,%2f]", vector->x,vector->y,vector->z);
	
	}
    else
    {
        xr_sprintf(buffer, "(not implemented)");
    }
    return shared_str(buffer);
}
