package com.C9group34.socialnetworkproject.service;


import com.C9group34.socialnetworkproject.models.Role;
import com.C9group34.socialnetworkproject.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RoleService {

    @Autowired
    RoleRepository roleRepository;

    public Role createRole(Role r){
        return roleRepository.save(r);
    }

    public List<Role> getAllRoles(){
        return roleRepository.findAll();
    }
}
