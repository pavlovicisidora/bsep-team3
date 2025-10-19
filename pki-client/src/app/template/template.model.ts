export interface Template {
  id: number;
  name: string;
  issuer: {
    id: number;
    serialNumber: string;
    subjectDN: string;
  };
  commonNameRegex: string;
  subjectAlternativeNamesRegex: string | null;
  timeToLiveDays: number;
  keyUsage: string; 
  extendedKeyUsage: string; 
}

export interface TemplateCreate {
  name: string;
  issuerSerialNumber: string;
  commonNameRegex: string;
  subjectAlternativeNamesRegex?: string; 
  timeToLiveDays: number;
  keyUsage: string[];
  extendedKeyUsage: string[];
}

