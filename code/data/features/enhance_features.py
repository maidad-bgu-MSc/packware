import numpy as np

def enhance_features(feature_dict):
    """
    Enhance the existing feature set with derived features
    
    Parameters:
    feature_dict (dict): Dictionary containing the original features with keys:
        - 'sections': section-related features
        - 'headers': header-related features
        - 'generics': generic file features
        - 'imps': imported functions
        - 'exps': exported functions
        - 'dlls': imported DLLs
        - 'rich': rich header information
    
    Returns:
    dict: Enhanced feature dictionary with additional derived features
    """
    # Create a copy of original features
    enhanced_features = feature_dict.copy()
    derived = {}
    
    sections = feature_dict['sections']
    headers = feature_dict['headers']
    generics = feature_dict['generics']
    
    # 1. Section-based Relationships
    try:
        if sections['pesectionProcessed_sectionsMinSize'] != 0:
            derived['derived_sectionSizeRatio'] = sections['pesectionProcessed_sectionsMaxSize'] / sections['pesectionProcessed_sectionsMinSize']
        else:
            derived['derived_sectionSizeRatio'] = 0
            
        if sections['pesectionProcessed_sectionsMeanSize'] != 0:
            derived['derived_virtualToRawRatio'] = sections['pesectionProcessed_sectionsMeanVirtualSize'] / sections['pesectionProcessed_sectionsMeanSize']
        else:
            derived['derived_virtualToRawRatio'] = 0
            
        # Entropy relationships
        derived['derived_entropyVariance'] = sections['pesectionProcessed_sectionsMaxEntropy'] - sections['pesectionProcessed_sectionsMinEntropy']
        derived['derived_meanToMaxEntropyRatio'] = sections['pesectionProcessed_sectionsMeanEntropy'] / sections['pesectionProcessed_sectionsMaxEntropy'] if sections['pesectionProcessed_sectionsMaxEntropy'] != 0 else 0
    except KeyError:
        derived.update({
            'derived_sectionSizeRatio': 0,
            'derived_virtualToRawRatio': 0,
            'derived_entropyVariance': 0,
            'derived_meanToMaxEntropyRatio': 0
        })

    # 2. Size Relationships
    try:
        if generics['generic_fileSize'] != 0:
            derived['derived_headerSizeRatio'] = headers['header_SizeOfHeaders'] / generics['generic_fileSize']
            derived['derived_codeSizeRatio'] = headers['header_SizeOfCode'] / generics['generic_fileSize']
            derived['derived_entropyToSizeRatio'] = generics['generic_fileEntropy'] / generics['generic_fileSize']
            derived['derived_uninitializedRatio'] = headers['header_SizeOfUninitializedData'] / generics['generic_fileSize']
            derived['derived_initializedRatio'] = headers['header_SizeOfInitializedData'] / generics['generic_fileSize']
        else:
            derived.update({
                'derived_headerSizeRatio': 0,
                'derived_codeSizeRatio': 0,
                'derived_entropyToSizeRatio': 0,
                'derived_uninitializedRatio': 0,
                'derived_initializedRatio': 0
            })
    except KeyError:
        derived.update({
            'derived_headerSizeRatio': 0,
            'derived_codeSizeRatio': 0,
            'derived_entropyToSizeRatio': 0,
            'derived_uninitializedRatio': 0,
            'derived_initializedRatio': 0
        })

    # 3. Import/Export Analysis
    imps = set(feature_dict['imps'])
    exps = set(feature_dict['exps'])
    dlls = set(feature_dict['dlls'])
    
    # API Categories
    api_categories = {
        'network': {'socket', 'connect', 'send', 'recv', 'bind', 'listen', 'accept', 'inet', 'http', 'ftp'},
        'file': {'file', 'read', 'write', 'create', 'delete', 'move', 'copy', 'find'},
        'registry': {'reg', 'registry', 'hkey'},
        'process': {'process', 'thread', 'virtual', 'memory', 'alloc', 'free'},
        'crypto': {'crypt', 'decrypt', 'encrypt', 'hash', 'rc4', 'aes', 'rsa'},
        'ui': {'window', 'dialog', 'gui', 'menu', 'button', 'display'}
    }
    
    # Calculate API category ratios
    total_apis = len(imps)
    if total_apis > 0:
        for category, keywords in api_categories.items():
            category_count = sum(1 for imp in imps if any(keyword in imp.lower() for keyword in keywords))
            derived[f'derived_{category}ApisRatio'] = category_count / total_apis
    else:
        for category in api_categories:
            derived[f'derived_{category}ApisRatio'] = 0
            
    # Import/Export relationships
    derived['derived_importToExportRatio'] = len(imps) / len(exps) if len(exps) > 0 else len(imps)
    derived['derived_avgImportsPerDll'] = len(imps) / len(dlls) if len(dlls) > 0 else 0
    
    # 4. Resource Analysis
    try:
        if 'pesectionProcessed_resources_nb' in sections:
            if generics['generic_fileSize'] > 0:
                derived['derived_resourceDensity'] = sections['pesectionProcessed_resources_nb'] / (generics['generic_fileSize'] / 1024)
            else:
                derived['derived_resourceDensity'] = 0
                
            if sections['pesectionProcessed_resources_nb'] > 0:
                derived['derived_resourceComplexity'] = sections['pesectionProcessed_resourcesMeanSize'] * sections['pesectionProcessed_resourcesMeanEntropy']
                derived['derived_resourceSizeVariance'] = (sections['pesectionProcessed_resourcesMaxSize'] - sections['pesectionProcessed_resourcesMinSize']) / sections['pesectionProcessed_resourcesMeanSize'] if sections['pesectionProcessed_resourcesMeanSize'] != 0 else 0
            else:
                derived['derived_resourceComplexity'] = 0
                derived['derived_resourceSizeVariance'] = 0
    except KeyError:
        derived.update({
            'derived_resourceDensity': 0,
            'derived_resourceComplexity': 0,
            'derived_resourceSizeVariance': 0
        })
    
    # 5. Complexity Metrics
    # Normalize and combine various metrics to create complexity scores
    try:
        size_complexity = np.log1p(generics['generic_fileSize']) / 20  # normalize size impact
        entropy_complexity = generics['generic_fileEntropy'] / 8  # entropy is typically 0-8
        import_complexity = np.log1p(len(imps)) / 10
        section_complexity = sections['pesectionProcessed_sectionsMaxEntropy'] * len(dlls) / 100
        
        derived['derived_overallComplexity'] = (size_complexity + entropy_complexity + import_complexity + section_complexity) / 4
    except (KeyError, ValueError):
        derived['derived_overallComplexity'] = 0
    
    # Add derived features to the enhanced features dictionary
    enhanced_features['derived'] = derived
    
    return enhanced_features
